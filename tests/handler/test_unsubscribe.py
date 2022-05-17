from dataclasses import dataclass
from email.message import Message
from typing import Iterable

import pytest

from app.config import URL
from app.db import Session
from app.email import headers
from app.handler.unsubscribe import (
    UnsubscribeAction,
    UnsubscribeData,
    UnsubscribeEncoder,
    UnsubscribeGenerator,
)
from app.models import Alias, Contact
from tests.utils import create_new_user

legacy_test_data = [
    ("3=", UnsubscribeData(UnsubscribeAction.DisableAlias, 3)),
    ("438_", UnsubscribeData(UnsubscribeAction.DisableContact, 438)),
    ("4325*", UnsubscribeData(UnsubscribeAction.UnsubscribeNewsletter, 4325)),
]


@pytest.mark.parametrize("serialized_data, expected", legacy_test_data)
def test_decode_legacy_unsub(serialized_data, expected):
    info = UnsubscribeEncoder.decode_unsubscribe_payload(serialized_data)
    assert expected == info


encode_decode_test_data = [
    UnsubscribeData(UnsubscribeAction.DisableContact, 3),
    UnsubscribeData(UnsubscribeAction.DisableContact, 10),
    UnsubscribeData(UnsubscribeAction.DisableAlias, 101),
    UnsubscribeData(
        UnsubscribeAction.OriginalUnsubscribeMailto,
        [("a@b.com", "some subject goes here")],
    ),
    UnsubscribeData(
        UnsubscribeAction.OriginalUnsubscribeMailto,
        [("a@b.com", "some other"), ("b@c.d", "More")],
    ),
]


@pytest.mark.parametrize("unsub_data", encode_decode_test_data)
def test_encode_decode_unsub(unsub_data):
    encoded = UnsubscribeEncoder.encode_unsubscribe_data(unsub_data)
    decoded = UnsubscribeEncoder.decode_unsubscribe_payload(encoded)
    assert unsub_data.action == decoded.action
    assert unsub_data.data == decoded.data


TEST_UNSUB_EMAIL = "unsub@sl.com"


def generate_unsub_test_original_unsub_data() -> Iterable:
    user = create_new_user()
    user.original_unsub = True
    alias = Alias.create_new_random(user)
    Session.commit()
    contact = Contact.create(
        user_id=user.id,
        alias_id=alias.id,
        website_email="contact@example.com",
        reply_email="rep@sl.local",
        commit=True,
    )

    yield (
        user,
        alias,
        contact,
        True,
        "<http://lol.com>, <mailto:somewhere@not.net>",
        "<http://lol.com>",
    )
    yield (
        user,
        alias,
        contact,
        False,
        "<http://lol.com>, <mailto:somewhere@not.net>",
        "<http://lol.com>",
    )
    unsub_data = UnsubscribeEncoder.encode_unsubscribe_data(
        UnsubscribeData(
            UnsubscribeAction.OriginalUnsubscribeMailto, ["test@test.com", "hello"]
        )
    )
    yield (
        user,
        alias,
        contact,
        True,
        "<mailto:test@test.com?subject=hello>",
        f"<{TEST_UNSUB_EMAIL}?subject={unsub_data}",
    )
    yield (
        user,
        alias,
        contact,
        False,
        "<mailto:test@test.com?subject=hello>",
        f"<{URL}/dashboard/unsubscribe?request={unsub_data}",
    )
    yield (user, alias, contact, True, None, None)
    yield (user, alias, contact, False, None, None)


@pytest.mark.parametrize(
    "user, alias, contact, unsub_mailto, original_header, expected_header",
    generate_unsub_test_original_unsub_data(),
)
def test_generate_unsub_header(
    user, alias, contact, unsub_mailto, original_header, expected_header
):
    message = Message()
    message[headers.LIST_UNSUBSCRIBE] = original_header
    message = UnsubscribeGenerator.add_header_to_message(message)
    if unsub_mailto:
        assert message[headers.LIST_UNSUBSCRIBE_POST] is None
    else:
        assert "List-Unsubscribe=One-Click" == message[headers.LIST_UNSUBSCRIBE_POST]
    assert expected_header == message[headers.LIST_UNSUBSCRIBE]
