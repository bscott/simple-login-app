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
    data: Union[List[Tuple[str, str]], int]


class UnsubscribeEncoder:
    @staticmethod
    def _get_signer() -> itsdangerous.Signer:
        return itsdangerous.Signer(UNSUBSCRIBE_SECRET, digest_method=hashlib.sha3_224)

    @staticmethod
    def encode_unsubscribe_data(unsub: UnsubscribeData) -> str:
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
    def set_unsubscribe_header(
        cls, message: Message, unsub: UnsubscribeData
    ) -> Message:
        unsub_payload = cls.encode_unsubscribe_data(unsub)
        if UNSUBSCRIBER:
            unsub_mailto = f"mailto:{UNSUBSCRIBER}?subject={unsub_payload}", True
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

    @classmethod
    def extract_from_unsubscribe_header(
        cls, message: Message
    ) -> Optional[UnsubscribeData]:
        data = message[headers.LIST_UNSUBSCRIBE]
        if not data:
            return None
        return cls.decode_unsubscribe_payload(data)

    @classmethod
    def decode_unsubscribe_payload(cls, data: str) -> Optional[UnsubscribeData]:
        if data.find(UNSUB_PREFIX) == -1:
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
                return UnsubscribeData(UnsubscribeAction.UnsubscribeNewsletter, user_id)
            else:
                LOG.info(f"Invalid unsubscribe data: {data}")
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
            action_data = [tuple(mail_data) for mail_data in action_data]
        return UnsubscribeData(action, action_data)


class UnsubscribeGenerator:
    def __init__(self, unsubscribe_email: Optional[str] = None):
        self.unsubscribe_email = unsubscribe_email or UNSUBSCRIBER

    def _generate_header_with_original_behaviour(self, message: Message) -> Message:
        unsubscribe_data = message[headers.LIST_UNSUBSCRIBE]
        if not unsubscribe_data:
            return message
        raw_methods = [method.strip() for method in unsubscribe_data.split(",")]
        mailto_unsubs = []
        other_unsubs = []
        for raw_method in raw_methods:
            start = raw_method.find("<")
            end = raw_method.rfind(">")
            if start == -1 or end == -1 or start >= end:
                continue
            method = raw_method[start + 1 : end]
            urldata = urllib.parse.urlparse(method)
            if urldata.scheme == "mailto":
                mailto_unsubs.append(method)
            other_unsubs.append(method)
        # If there are non mailto unsubscribe methods, use those in the header
        if other_unsubs:
            message[headers.LIST_UNSUBSCRIBE] = ", ".join(
                [f"<{method}>" for method in other_unsubs]
            )
            return message
        return UnsubscribeEncoder.set_unsubscribe_header(
            message, UnsubscribeAction.OriginalUnsubscribeMailto, mailto_unsubs
        )

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
        user = alias.user
        if user.setting:
            return self._generate_header_with_original_behaviour(message)
        else:
            return self._generate_header_with_sl_behaviour(alias, contact, message)


class UnsubscribeHandler:
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

    def handle_unsubscribe(self, envelope: Envelope, msg: Message) -> str:
        """return the SMTP status"""
        # format: alias_id:
        subject = msg[headers.SUBJECT]

        try:
            # subject has the format {alias.id}=
            if subject.endswith("="):
                alias_id = int(subject[:-1])
                return self._disable_alias(alias_id)
            # {contact.id}_
            elif subject.endswith("_"):
                contact_id = int(subject[:-1])
                return self._disable_contact(contact_id)
            # {user.id}*
            elif subject.endswith("*"):
                user_id = int(subject[:-1])
                return self._unsubscribe_user_from_newsletter(
                    user_id, envelope.mail_from
                )
            # some email providers might strip off the = suffix
            else:
                alias_id = int(subject)
                return self._disable_alias(alias_id)
        except Exception:
            LOG.w("Wrong format subject %s", msg[headers.SUBJECT])
            return status.E507

    def _disable_alias(self, alias_id: int, envelope: Envelope) -> str:
        alias = Alias.get(alias_id)
        if not alias:
            return status.E508

        mail_from = envelope.mail_from
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

    def _disable_contact(self, contact_id: int, envelope: Envelope) -> str:
        contact = Contact.get(contact_id)
        if not contact:
            return status.E508

        mail_from = envelope.mail_from
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
