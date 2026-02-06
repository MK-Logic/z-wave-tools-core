/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using System;
using ZWave.BasicApplication.Enums;
using ZWave.Enums;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Sends the TX report back to the module for a prior Request Protocol CC Encryption (0x6C) flow.
    /// HOST->ZW: REQ | 0x6C | session_id | tx_status | tx_report...
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
            return new byte[]
            {
                SessionId,
                TxStatus,
                (byte)((r?.TransmitTicks ?? 0) >> 8),
                (byte)((r?.TransmitTicks ?? 0) & 0xFF),
                r?.RepeatersCount ?? 0,
                (byte)(r?.AckRssi ?? 0),
                (byte)rssi0,
                (byte)rssi1,
                (byte)rssi2,
                (byte)rssi3,
                r?.AckChannelNo ?? 0,
                r?.LastTxChannelNo ?? 0,
                (byte)(r?.RouteScheme ?? 0),
                rep0,
                rep1,
                rep2,
                rep3,
                beamSpeedByte,
                r?.RouteTries ?? 0,
                r?.LastFailedLinkFrom ?? 0,
                r?.LastFailedLinkTo ?? 0,
                (byte)(r?.UsedTxpower ?? 0),
                (byte)(r?.MeasuredNoiseFloor ?? 0),
                (byte)(r?.AckDestinationUsedTxPower ?? 0),
                (byte)(r?.DestinationAckMeasuredRSSI ?? 0),
                (byte)(r?.DestinationckMeasuredNoiseFloor ?? 0),
            };
        }

        protected override ActionResult CreateOperationResult()
        {
            return new ActionResult();
        }
    }
}
