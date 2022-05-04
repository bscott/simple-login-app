from email.message import Message
from typing import Optional

from aiosmtpd.smtp import Envelope

from app.config import URL
from app.db import Session
from app.email import headers, status
from app.email_utils import send_email, render
from app.log import LOG
from app.models import Alias, Contact, User, Mailbox


class UnsubscribeEncoder:


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
                return self._unsubscribe_user_from_newsletter(user_id, envelope.mail_from)
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
        """ return if the email_address is authorized to unsubscribe from an alias or block a contact
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
