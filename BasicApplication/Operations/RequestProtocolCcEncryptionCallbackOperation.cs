/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using System;
using System.Collections.Generic;
using ZWave.BasicApplication.Enums;
using ZWave.Enums;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Sends the TX report back to the module for a prior Request Protocol CC Encryption (0x6C) flow.
    /// HOST->ZW: REQ | 0x6C (Request Protocol CC Encryption) | session_id | tx_status | tx_report...
    /// Call after <see cref="ControllerNodeSendProtocolDataOperation"/> completes to report transmit result.
    /// </summary>
    public class RequestProtocolCcEncryptionCallbackOperation : ApiOperation
    {
        public byte SessionId { get; set; }
        public byte TxStatus { get; set; }
        public SendDataResult TxReport { get; set; }

        public RequestProtocolCcEncryptionCallbackOperation(byte sessionId, byte txStatus, SendDataResult txReport)
            : base(false, CommandTypes.CmdZWaveRequestProtocolCcEncryption, false)
        {
            SessionId = sessionId;
            TxStatus = txStatus;
            TxReport = txReport;
        }

        private ApiMessage _message;

        protected override void CreateWorkflow()
        {
            ActionUnits.Add(new StartActionUnit(SetStateCompleting, 0, _message));
        }

        protected override void CreateInstance()
        {
            _message = new ApiMessage(SerialApiCommands[0], CreateCallbackPayload());
            _message.IsSequenceNumberRequired = false;
        }

        private byte[] CreateCallbackPayload()
        {
            var r = TxReport;
            var payload = new List<byte>
            {
                SessionId,
                TxStatus,
            };

            // Only append TX report fields when the report exists.
            // This avoids sending a synthetic full report (all zeros) when module did not provide one.
            if (r == null || !r.HasTxTransmitReport)
            {
                return payload.ToArray();
            }

            byte[] rep = r?.Repeaters;
            byte rep0 = (rep != null && rep.Length > 0) ? rep[0] : (byte)0;
            byte rep1 = (rep != null && rep.Length > 1) ? rep[1] : (byte)0;
            byte rep2 = (rep != null && rep.Length > 2) ? rep[2] : (byte)0;
            byte rep3 = (rep != null && rep.Length > 3) ? rep[3] : (byte)0;
            sbyte[] rssi = r?.RssiValuesIncoming;
            sbyte rssi0 = (rssi != null && rssi.Length > 0) ? rssi[0] : (sbyte)0;
            sbyte rssi1 = (rssi != null && rssi.Length > 1) ? rssi[1] : (sbyte)0;
            sbyte rssi2 = (rssi != null && rssi.Length > 2) ? rssi[2] : (sbyte)0;
            sbyte rssi3 = (rssi != null && rssi.Length > 3) ? rssi[3] : (sbyte)0;
            byte beamSpeedByte = r?.BeamSpeedByte ?? (byte)((r?.RouteSpeed ?? 0) & 0x07);
            payload.Add((byte)((r?.TransmitTicks ?? 0) >> 8));
            payload.Add((byte)((r?.TransmitTicks ?? 0) & 0xFF));
            payload.Add(r?.RepeatersCount ?? 0);
            payload.Add((byte)(r?.AckRssi ?? 0));
            payload.Add((byte)rssi0);
            payload.Add((byte)rssi1);
            payload.Add((byte)rssi2);
            payload.Add((byte)rssi3);
            payload.Add(r?.AckChannelNo ?? 0);
            payload.Add(r?.LastTxChannelNo ?? 0);
            payload.Add((byte)(r?.RouteScheme ?? 0));
            payload.Add(rep0);
            payload.Add(rep1);
            payload.Add(rep2);
            payload.Add(rep3);
            payload.Add(beamSpeedByte);
            payload.Add(r?.RouteTries ?? 0);
            payload.Add(r?.LastFailedLinkFrom ?? 0);
            payload.Add(r?.LastFailedLinkTo ?? 0);
            payload.Add((byte)(r?.UsedTxpower ?? 0));
            payload.Add((byte)(r?.MeasuredNoiseFloor ?? 0));
            payload.Add((byte)(r?.AckDestinationUsedTxPower ?? 0));
            payload.Add((byte)(r?.DestinationAckMeasuredRSSI ?? 0));
            payload.Add((byte)(r?.DestinationckMeasuredNoiseFloor ?? 0));

            return payload.ToArray();
        }

        protected override ActionResult CreateOperationResult()
        {
            return new ActionResult();
        }
    }
}
