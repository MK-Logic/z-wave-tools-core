// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using System.Linq;
using ZWave.CommandClasses;

namespace ZWave.ZnifferApplication
{
    /// <summary>
    /// Removes the Wake On Critical Message Notify encapsulation from sniffed frames.
    /// The Notify Command is the outermost layer (outside of S2), so call <see cref="Parse"/>
    /// before <see cref="SecurityManager.ParseSecurity"/> to let S2 tracking and decryption see the encapsulated frame.
    /// </summary>
    public static class WakeOnCriticalMessageParser
    {
        private const int NOTIFY_HEADER_LENGTH = 4; // Command Class, Command, Properties1 (Severity), Payload Length

        /// <summary>
        /// Adds the encapsulated payload as carry payload if the last payload of the data item is a Notify Command
        /// whose Payload Length matches the received data.
        /// Calling it again is harmless, because the last payload is then the encapsulated payload.
        /// </summary>
        /// <returns>True if the encapsulated payload was added.</returns>
        public static bool Parse(DataItem dataItem)
        {
            if (!TryGetNotify(dataItem?.LastPayload, out var notify))
            {
                return false;
            }
            dataItem.AddExtension(DataItemExtensionTypes.CarryPayload, notify.encapsulatedPayload.ToArray());
            return true;
        }

        /// <summary>
        /// Returns true if the payload is a Notify Command whose Payload Length matches the payload.
        /// </summary>
        public static bool IsValidNotify(byte[] payload)
        {
            return TryGetNotify(payload, out _);
        }

        private static bool TryGetNotify(byte[] payload,
            out COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY notify)
        {
            notify = null;
            if (payload == null || payload.Length < 2 ||
                payload[0] != COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID ||
                payload[1] != COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY.ID)
            {
                return false;
            }
            notify = payload;
            // The generated parser silently truncates or ignores surplus bytes,
            // so check the Payload Length against the received data.
            return notify.payloadLength > 0 &&
                payload.Length == NOTIFY_HEADER_LENGTH + notify.payloadLength;
        }
    }
}
