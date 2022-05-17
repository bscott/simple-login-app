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
    info = UnsubscribeEncoder.decode(serialized_data)
    assert expected == info


encode_decode_test_data = [
    UnsubscribeData(UnsubscribeAction.DisableContact, 3),
    UnsubscribeData(UnsubscribeAction.DisableContact, 10),
    UnsubscribeData(UnsubscribeAction.DisableAlias, 101),
    UnsubscribeData(
        UnsubscribeAction.OriginalUnsubscribeMailto,
        (323, "a@b.com", "some subject goes here"),
    ),
]


@pytest.mark.parametrize("unsub_data", encode_decode_test_data)
def test_encode_decode_unsub(unsub_data):
    encoded = UnsubscribeEncoder.encode(unsub_data)
    decoded = UnsubscribeEncoder.decode(encoded)
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
        "<https://lol.com>, <mailto:somewhere@not.net>",
        "<https://lol.com>",
    )
    yield (
        user,
        alias,
        contact,
        False,
        "<https://lol.com>, <mailto:somewhere@not.net>",
        "<https://lol.com>",
    )
    unsub_data = UnsubscribeEncoder.encode(
        UnsubscribeData(
            UnsubscribeAction.OriginalUnsubscribeMailto,
            (alias.id, "test@test.com", "hello"),
        )
    )
    yield (
        user,
        alias,
        contact,
        True,
        "<mailto:test@test.com?subject=hello>",
        f"<mailto:{TEST_UNSUB_EMAIL}?subject={unsub_data}>",
    )
    yield (
        user,
        alias,
        contact,
        False,
        "<mailto:test@test.com?subject=hello>",
        f"<{URL}/dashboard/unsubscribe?request={unsub_data}>",
    )
    yield (user, alias, contact, True, None, None)
    yield (user, alias, contact, False, None, None)


@pytest.mark.parametrize(
    "user, alias, contact, unsub_via_mail, original_header, expected_header",
    generate_unsub_test_original_unsub_data(),
)
def test_generate_unsub_header(
    user, alias, contact, unsub_via_mail, original_header, expected_header
):
    message = Message()
    message[headers.LIST_UNSUBSCRIBE] = original_header
    message = UnsubscribeGenerator(
        TEST_UNSUB_EMAIL if unsub_via_mail else None
    ).add_header_to_message(alias, contact, message)
    assert expected_header == message[headers.LIST_UNSUBSCRIBE]
    if not expected_header or expected_header.find("<http") == -1:
        assert message[headers.LIST_UNSUBSCRIBE_POST] is None
    else:
        assert "List-Unsubscribe=One-Click" == message[headers.LIST_UNSUBSCRIBE_POST]
