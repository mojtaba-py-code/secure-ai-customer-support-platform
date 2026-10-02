"""Outgoing e-mail (password resets).

* ``SmtpEmailSender`` - production: STARTTLS with certificate verification, authenticated,
  bounded by a timeout, run in a worker thread.
* ``DevMailboxSender`` - development only (refused in production by settings validation): writes
  each message to ``var/mailbox`` so a developer can open reset links without an SMTP server.
* ``DisabledEmailSender`` - drops messages (logs the event, never the content).
"""

from __future__ import annotations

import asyncio
import logging
import os
import smtplib
import ssl
import uuid
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class OutgoingEmail:
    to: str
    subject: str
    body: str


class EmailSender(Protocol):
    async def send(self, message: OutgoingEmail) -> None: ...


def _build(message: OutgoingEmail, sender: str) -> EmailMessage:
    email = EmailMessage()
    email["From"] = sender
    email["To"] = message.to
    email["Subject"] = message.subject
    email.set_content(message.body)
    return email


class DisabledEmailSender:
    async def send(self, message: OutgoingEmail) -> None:
        logger.info("email delivery disabled; message dropped", extra={"event": "email.dropped"})


class DevMailboxSender:
    def __init__(self, directory: str, sender: str) -> None:
        self._directory = Path(directory)
        self._sender = sender

    async def send(self, message: OutgoingEmail) -> None:
        await asyncio.to_thread(self._write, message)

    def _write(self, message: OutgoingEmail) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        path = self._directory / f"{uuid.uuid4().hex}.eml"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_build(message, self._sender).as_string())
        logger.info(
            "email written to development mailbox",
            extra={"event": "email.dev_mailbox", "file": path.name},
        )


class SmtpEmailSender:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        sender: str,
        timeout_seconds: float,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._sender = sender
        self._timeout = timeout_seconds

    async def send(self, message: OutgoingEmail) -> None:
        await asyncio.to_thread(self._send_sync, message)

    def _send_sync(self, message: OutgoingEmail) -> None:
        context = ssl.create_default_context()
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            smtp.starttls(context=context)
            if self._username and self._password:
                smtp.login(self._username, self._password)
            smtp.send_message(_build(message, self._sender))
        logger.info("email sent", extra={"event": "email.sent"})
