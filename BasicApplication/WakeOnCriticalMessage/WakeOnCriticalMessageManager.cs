// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using System;
using System.Collections.Generic;
using System.Linq;
using ZWave.BasicApplication.Operations;
using ZWave.CommandClasses;
using ZWave.Devices;
using ZWave.Enums;
using ZWave.Layers.Frame;

namespace ZWave.BasicApplication
{
    /// <summary>
    /// Handles the Wake On Critical Message Notify Command, which is always the outermost encapsulation layer
    /// (outside of S2).
    /// Incoming: removes the Notify encapsulation before any other layer (e.g. S2) is processed.
    /// Outgoing: wraps frames sent with <see cref="SubstituteFlags.UseWakeOnCriticalMessage"/> after all other layers.
    /// Limitation: with the End Device Serial API and the Sample Application, security is handled by the firmware.
    /// Therefore only non-secure frames are supported:
    /// - Outgoing: an action sent with a security scheme fails without sending anything.
    /// - Incoming: a Notify Command that contains an S0 or S2 encapsulation is not decapsulated.
    /// </summary>
    public class WakeOnCriticalMessageManager : SubstituteManagerBase
    {
        private const int NOTIFY_HEADER_LENGTH = 4; // Command Class, Command, Properties1 (Severity), Payload Length

        /// <summary>
        /// Severity (1..7) written to outgoing Notify Commands. Values outside the range are sent as given
        /// (masked to 3 bits) to allow negative testing.
        /// </summary>
        public byte Severity { get; set; } = 1;

        public WakeOnCriticalMessageManager(NetworkViewPoint network)
            : base(network)
        { }

        protected override SubstituteIncomingFlags GetId()
        {
            return SubstituteIncomingFlags.WakeOnCriticalMessage;
        }

        protected override CustomDataFrame SubstituteIncomingInternal(CustomDataFrame packet, NodeTag destNode, NodeTag srcNode, byte[] cmdData, int lenIndex, out ActionBase additionalAction, out ActionBase completeAction)
        {
            CustomDataFrame ret = packet;
            additionalAction = null;
            completeAction = null;
            // If security is handled by the firmware, it hasn't seen the security encapsulation inside the
            // Notify Command, and the host can't process it. The Notify Command is left for the test case.
            if (IsActive && TryGetNotify(cmdData, out var notify) &&
                !(IsSecurityHandledByFirmware() && IsSecurityEncapsulation(notify.encapsulatedPayload)))
            {
                byte[] encapsulatedPayload = notify.encapsulatedPayload.ToArray();
                byte[] newFrameData = new byte[packet.Data.Length - NOTIFY_HEADER_LENGTH];
                Array.Copy(packet.Data, 0, newFrameData, 0, lenIndex);
                newFrameData[lenIndex] = (byte)encapsulatedPayload.Length;
                Array.Copy(encapsulatedPayload, 0, newFrameData, lenIndex + 1, encapsulatedPayload.Length);
                Array.Copy(packet.Data, lenIndex + 1 + cmdData.Length, newFrameData, lenIndex + 1 + encapsulatedPayload.Length,
                    packet.Data.Length - lenIndex - 1 - cmdData.Length);
                ret = CreateNewFrame(packet, newFrameData);
            }
            return ret;
        }

        /// <summary>
        /// Only a Notify Command whose Payload Length matches the received data is decapsulated.
        /// Other spec rules (severity, payload length limit, allowed payloads) are left to the test cases,
        /// which can still inspect the original frame.
        /// </summary>
        private static bool TryGetNotify(byte[] cmdData,
            out COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY notify)
        {
            notify = null;
            if (cmdData == null || cmdData.Length < 2 ||
                cmdData[0] != COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID ||
                cmdData[1] != COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY.ID)
            {
                return false;
            }
            notify = cmdData;
            // The generated parser silently truncates or ignores surplus bytes,
            // so check the Payload Length against the received data.
            return notify.payloadLength > 0 &&
                cmdData.Length == NOTIFY_HEADER_LENGTH + notify.payloadLength;
        }

        public override ActionBase SubstituteActionInternal(ApiOperation action)
        {
            ActionBase ret = null;
            if (IsActive && action.SubstituteSettings.HasFlag(SubstituteFlags.UseWakeOnCriticalMessage))
            {
                byte[] data = GetData(action);
                // Data is null for S2 messages that only carry extensions (e.g. the MPAN answer to MOS).
                if (data != null && data.Length > 1 && data[0] != COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID)
                {
                    if (IsEncryptedByFirmware(action))
                    {
                        // Fail instead of silently sending the frame without the Notify Command.
                        return new RejectedOperation(
                            "Wake On Critical Message can't be used with a security scheme on an End Device library, " +
                            "because the firmware encrypts the frame and the Notify Command would end up inside S2");
                    }
                    var notify = new COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY();
                    notify.properties1.severity = Severity;
                    notify.payloadLength = (byte)data.Length;
                    notify.encapsulatedPayload = data.ToList();
                    if (SetData(action, notify))
                    {
                        ret = action;
                    }
                }
            }
            return ret;
        }

        /// <summary>
        /// With the End Device Serial API and the Sample Application, the firmware handles security.
        /// </summary>
        private bool IsSecurityHandledByFirmware()
        {
            return _network.Library.IsSerialApiEndDevice() || _network.Library.IsSampleApplication();
        }

        /// <summary>
        /// Frames sent with a security scheme are encrypted by the firmware (see <see cref="IsSecurityHandledByFirmware"/>).
        /// Wrapping them in the host would put the Notify Command inside S2.
        /// </summary>
        private bool IsEncryptedByFirmware(ApiOperation action)
        {
            return IsSecurityHandledByFirmware() &&
                action is SendDataExOperation sendDataEx &&
                sendDataEx.SecurityScheme != SecuritySchemes.NONE;
        }

        private static bool IsSecurityEncapsulation(IList<byte> payload)
        {
            return payload.Count > 0 &&
                (payload[0] == COMMAND_CLASS_SECURITY_2.ID || payload[0] == COMMAND_CLASS_SECURITY.ID);
        }

        private static byte[] GetData(ApiOperation action)
        {
            switch (action)
            {
                case SendDataOperation sendData:
                    return sendData.Data;
                case SendDataBridgeOperation sendDataBridge:
                    return sendDataBridge.Data;
                case SendDataExOperation sendDataEx:
                    return sendDataEx.Data;
                default:
                    return null;
            }
        }

        private static bool SetData(ApiOperation action, byte[] data)
        {
            switch (action)
            {
                case SendDataOperation sendData:
                    sendData.Data = data;
                    return true;
                case SendDataBridgeOperation sendDataBridge:
                    sendDataBridge.Data = data;
                    return true;
                case SendDataExOperation sendDataEx:
                    sendDataEx.Data = data;
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>
        /// Replaces an action that can't be sent as requested, so that it fails without sending anything.
        /// The reason is part of the token name.
        /// </summary>
        private class RejectedOperation : ActionBase
        {
            private readonly string _reason;

            public RejectedOperation(string reason)
                : base(false)
            {
                _reason = reason;
            }

            protected override void CreateInstance()
            { }

            protected override void CreateWorkflow()
            {
                ActionUnits.Add(new StartActionUnit(SetStateFailed, 0));
            }

            public override string AboutMe()
            {
                return _reason;
            }
        }
    }
}
