import base64
import hashlib
import hmac
import json
import urllib.parse
from dataclasses import dataclass
from email.message import Message
from typing import List, Optional, Union, Tuple

import itsdangerous
from aiosmtpd.smtp import Envelope

from app.config import URL, UNSUBSCRIBER, UNSUBSCRIBE_SECRET
from app.db import Session
from app.email import headers, status
from app.email_utils import send_email, render, add_or_replace_header, delete_header
from app.log import LOG
from app.models import Alias, Contact, User, EnumE


UNSUB_PREFIX = "unsub"


class UnsubscribeAction(EnumE):
    UnsubscribeNewsletter = 1
    DisableAlias = 2
    DisableContact = 3
    OriginalUnsubscribeMailto = 4


@dataclass
class UnsubscribeData:
    action: UnsubscribeAction
    data: Union[Tuple[int, str, str], int]


class UnsubscribeEncoder:
    @staticmethod
    def _get_signer() -> itsdangerous.Signer:
        return itsdangerous.Signer(UNSUBSCRIBE_SECRET, digest_method=hashlib.sha3_224)

    @staticmethod
    def encode(unsub: UnsubscribeData) -> str:
        payload = (unsub.action.value, unsub.data)
        serialized_data = (
            base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
            .rstrip(b"=")
            .decode("utf-8")
        )
        signer = itsdangerous.Signer(UNSUBSCRIBE_SECRET, digest_method=hashlib.sha3_224)
        signed_data = signer.sign(serialized_data).decode("utf-8")
        return f"{UNSUB_PREFIX}.{signed_data}"

    @classmethod
    def decode(cls, data: str) -> Optional[UnsubscribeData]:
        if data.find(UNSUB_PREFIX) == -1:
            try:
                # subject has the format {alias.id}=
                if data.endswith("="):
                    alias_id = int(data[:-1])
                    return UnsubscribeData(UnsubscribeAction.DisableAlias, alias_id)
                # {contact.id}_
                elif data.endswith("_"):
                    contact_id = int(data[:-1])
                    return UnsubscribeData(UnsubscribeAction.DisableContact, contact_id)
                # {user.id}*
                elif data.endswith("*"):
                    user_id = int(data[:-1])
                    return UnsubscribeData(
                        UnsubscribeAction.UnsubscribeNewsletter, user_id
                    )
                else:
                    # some email providers might strip off the = suffix
                    alias_id = int(data)
                    return UnsubscribeData(UnsubscribeAction.DisableAlias, alias_id)
            except ValueError:
                return None
        signer = cls._get_signer()
        try:
            verified_data = signer.unsign(data[len(UNSUB_PREFIX) + 1 :])
        except itsdangerous.BadSignature:
            return None
        try:
            padded_data = verified_data + (b"=" * (-len(verified_data) % 4))
            payload = json.loads(base64.urlsafe_b64decode(padded_data))
        except ValueError:
            return None
        action = UnsubscribeAction(payload[0])
        action_data = payload[1]
        if action == UnsubscribeAction.OriginalUnsubscribeMailto:
            action_data = tuple(action_data)
        return UnsubscribeData(action, action_data)


class UnsubscribeGenerator:
    def __init__(self, unsubscribe_email: Optional[str] = None):
        self.unsubscribe_email = unsubscribe_email

    def _add_unsubscribe_header(self, message: Message, unsub_payload: str) -> Message:
        if self.unsubscribe_email:
            unsub_mailto = f"mailto:{self.unsubscribe_email}?subject={unsub_payload}"
            add_or_replace_header(
                message, headers.LIST_UNSUBSCRIBE, f"<{unsub_mailto}>"
            )
            delete_header(message, headers.LIST_UNSUBSCRIBE_POST)
        else:
            url = f"{URL}/dashboard/unsubscribe?request={unsub_payload}"
            add_or_replace_header(message, headers.LIST_UNSUBSCRIBE, f"<{url}>")
            add_or_replace_header(
                message, headers.LIST_UNSUBSCRIBE_POST, "List-Unsubscribe=One-Click"
            )
        return message

    def _generate_header_with_original_behaviour(
        self, alias: Alias, message: Message
    ) -> Message:
        unsubscribe_data = message[headers.LIST_UNSUBSCRIBE]
        if not unsubscribe_data:
            return message
        raw_methods = [method.strip() for method in unsubscribe_data.split(",")]
        mailto_unsubs = None
        other_unsubs = []
        for raw_method in raw_methods:
            start = raw_method.find("<")
            end = raw_method.rfind(">")
            if start == -1 or end == -1 or start >= end:
                continue
            method = raw_method[start + 1 : end]
            url_data = urllib.parse.urlparse(method)
            if url_data.scheme == "mailto":
                query_data = urllib.parse.parse_qs(url_data.query)
                mailto_unsubs = (url_data.path, query_data.get("subject", [""])[0])
            else:
                other_unsubs.append(method)
        # If there are non mailto unsubscribe methods, use those in the header
        if other_unsubs:
            add_or_replace_header(
                message,
                headers.LIST_UNSUBSCRIBE,
                ", ".join([f"<{method}>" for method in other_unsubs]),
            )
            add_or_replace_header(
                message, headers.LIST_UNSUBSCRIBE_POST, "List-Unsubscribe=One-Click"
            )
            return message
        unsub_payload = UnsubscribeEncoder.encode(
            UnsubscribeData(
                UnsubscribeAction.OriginalUnsubscribeMailto,
                (alias.id, mailto_unsubs[0], mailto_unsubs[1]),
            )
        )
        return self._add_unsubscribe_header(message, unsub_payload)

    def _generate_header_with_sl_behaviour(
        self, alias: Alias, contact: Contact, message: Message
    ) -> Message:
        user = alias.user
        if user.one_click_unsubscribe_block_sender:
            unsubscribe_link, via_email = alias.unsubscribe_link(contact)
        else:
            unsubscribe_link, via_email = alias.unsubscribe_link()

        add_or_replace_header(
            message, headers.LIST_UNSUBSCRIBE, f"<{unsubscribe_link}>"
        )
        if not via_email:
            add_or_replace_header(
                message, headers.LIST_UNSUBSCRIBE_POST, "List-Unsubscribe=One-Click"
            )
        return message

    def add_header_to_message(
        self, alias: Alias, contact: Contact, message: Message
    ) -> Message:
        """
        Add List-Unsubscribe header
        """
        if alias.user.original_unsub:
            return self._generate_header_with_original_behaviour(alias, message)
        else:
            return self._generate_header_with_sl_behaviour(alias, contact, message)


class UnsubscribeHandler:
    def _extract_unsub_info_from_message(
        self, message: Message
    ) -> Optional[UnsubscribeData]:
        header_value = message[headers.SUBJECT]
        if not header_value:
            return None
        return UnsubscribeEncoder.decode(header_value)

    def handle_unsubscribe_from_message(self, envelope: Envelope, msg: Message) -> str:
        unsub_data = self._extract_unsub_info_from_message(msg)
        if not unsub_data:
            LOG.w("Wrong format subject %s", msg[headers.SUBJECT])
            return status.E507
        if unsub_data.action == UnsubscribeAction.DisableAlias:
            return self._disable_alias(unsub_data.data, envelope.mail_from)
        elif unsub_data.action == UnsubscribeAction.DisableContact:
            return self._disable_contact(unsub_data.data, envelope.mail_from)
        elif unsub_data.action == UnsubscribeAction.UnsubscribeNewsletter:
            return self._unsubscribe_user_from_newsletter(
                unsub_data.data, envelope.mail_from
            )
        elif unsub_data.action == UnsubscribeAction.OriginalUnsubscribeMailto:
            return self._unsubscribe_original_behaviour(
                unsub_data.data, envelope.mail_from
            )
        else:
            raise Exception(f"Unknown unsubscribe action {unsub_data.action}")

    def _disable_alias(self, alias_id: int, mail_from: str) -> str:
        alias = Alias.get(alias_id)
        if not alias:
            return status.E508

        # Only alias's owning mailbox can send the unsubscribe request
        if not self._check_email_is_authorized_for_alias(mail_from, alias):
            return status.E509

        alias.enabled = False
        Session.commit()
        enable_alias_url = URL + f"/dashboard/?highlight_alias_id={alias.id}"
        for mailbox in alias.mailboxes:
            send_email(
                mailbox.email,
                f"Alias {alias.email} has been disabled successfully",
                render(
                    "transactional/unsubscribe-disable-alias.txt",
                    user=alias.user,
                    alias=alias.email,
                    enable_alias_url=enable_alias_url,
                ),
                render(
                    "transactional/unsubscribe-disable-alias.html",
                    user=alias.user,
                    alias=alias.email,
                    enable_alias_url=enable_alias_url,
                ),
            )
        return status.E202

    def _disable_contact(self, contact_id: int, mail_from: str) -> str:
        contact = Contact.get(contact_id)
        if not contact:
            return status.E508

        # Only alias's owning mailbox can send the unsubscribe request
        if not self._check_email_is_authorized_for_alias(mail_from, contact.alias):
            return status.E509

        alias = contact.alias
        contact.block_forward = True
        Session.commit()
        unblock_contact_url = (
            URL
            + f"/dashboard/alias_contact_manager/{alias.id}?highlight_contact_id={contact.id}"
        )
        for mailbox in alias.mailboxes:
            send_email(
                mailbox.email,
                f"Emails from {contact.website_email} to {alias.email} are now blocked",
                render(
                    "transactional/unsubscribe-block-contact.txt.jinja2",
                    user=alias.user,
                    alias=alias,
                    contact=contact,
                    unblock_contact_url=unblock_contact_url,
                ),
            )

        return status.E202

    def _unsubscribe_user_from_newsletter(self, user_id: int, mail_from: str) -> str:
        """return the SMTP status"""
        user = User.get(user_id)
        if not user:
            LOG.w("No such user %s %s", user_id, mail_from)
            return status.E510

        if mail_from != user.email:
            LOG.w("Unauthorized mail_from %s %s", user, mail_from)
            return status.E511

        user.notification = False
        Session.commit()

        send_email(
            user.email,
            "You have been unsubscribed from SimpleLogin newsletter",
            render(
                "transactional/unsubscribe-newsletter.txt",
                user=user,
            ),
            render(
                "transactional/unsubscribe-newsletter.html",
                user=user,
            ),
        )

        return status.E202

    def _check_email_is_authorized_for_alias(email_address: str, alias: Alias) -> bool:
        """return if the email_address is authorized to unsubscribe from an alias or block a contact
        Usually the mail_from=mailbox.email but it can also be one of the authorized address
        """
        for mailbox in alias.mailboxes:
            if mailbox.email == email_address:
                return True

            for authorized_address in mailbox.authorized_addresses:
                if authorized_address.email == email_address:
                    LOG.d(
                        "Found an authorized address for %s %s %s",
                        alias,
                        mailbox,
                        authorized_address,
                    )
                    return True

        LOG.d(
            "%s cannot disable alias %s. Alias authorized addresses:%s",
            email_address,
            alias,
            alias.authorized_addresses,
        )
        return False
