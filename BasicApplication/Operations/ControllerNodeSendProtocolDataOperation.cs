/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using System;
using ZWave.BasicApplication.Enums;
using ZWave.Devices;
using ZWave.Enums;
using Utils;
using System.Linq;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Sends encrypted protocol (Network Layer) data to the module for RF transmission (Controller Node Send Protocol Data (0xAC)).
    /// HOST->ZW: REQ | 0xAC | destination_node_id | data_length | data[] | protocol_metadata_length | protocol_metadata[] | session_id
    /// ZW->HOST: RES | 0xAC | RetVal
    /// ZW->HOST: REQ | 0xAC | session_id | txStatus | tx_report...
    /// Used for NLS; only call after receiving <see cref="RequestProtocolCcEncryptionOperation"/> and encrypting the payload.
    /// Unlike SendData (0x13), the 0xAC frame does NOT carry a funcId field. The session_id is the last byte.
    /// </summary>
    public class ControllerNodeSendProtocolDataOperation : CallbackApiOperation
    {
        public NodeTag DestinationNodeId { get; set; }
        public byte[] Data { get; set; }
        public byte[] ProtocolMetadata { get; set; }
        public byte SessionId { get; set; }

        public ControllerNodeSendProtocolDataOperation(NetworkViewPoint network, NodeTag destinationNodeId, byte[] encryptedData, byte[] protocolMetadata, byte sessionId)
            : base(CommandTypes.CmdZWaveControllerNodeSendProtocolData)
        {
            // Must run even when an exclusive parent operation is active (e.g. Neighbor Update waiting on NLS flow).
            IsExclusive = false;
            _network = network;
            DestinationNodeId = destinationNodeId;
            Data = encryptedData ?? Array.Empty<byte>();
            ProtocolMetadata = protocolMetadata ?? Array.Empty<byte>();
            SessionId = sessionId;
        }

        protected override void CreateInstance()
        {
            base.CreateInstance();
            // 0xAC does not have a funcId field; session_id is already in CreateInputParameters.
            // Prevent the framework from appending an extra SequenceNumber byte to the serial frame.
            Message.IsSequenceNumberRequired = false;
            TimeoutMs = SubstituteSettings.CallbackWaitTimeoutMs;
            SpecificResult.TransmitStatus = TransmitStatuses.ResMissing;
        }

        /// <summary>
        /// 0xAC callback uses Session identifier at data[2] (Data = [type, 0xAC, SessionId, TxStatus, ...]).
        /// ApiHandler already matches data[0]=Request, data[1]=0xAC; match data[2]=SessionId.
        /// </summary>
        protected override ByteIndex[] GetCallbackMatchConditions()
        {
            return new ByteIndex[] { new ByteIndex(SessionId) };
        }

        protected override byte[] CreateInputParameters()
        {
            int metaLen = ProtocolMetadata?.Length ?? 0;
            byte[] ret;
            if (_network.IsNodeIdBaseTypeLR)
            {
                ret = new byte[4 + Data.Length + 1 + metaLen + 1];
                ret[0] = (byte)(DestinationNodeId.Id >> 8);
                ret[1] = (byte)DestinationNodeId.Id;
                ret[2] = (byte)Data.Length;
                Buffer.BlockCopy(Data, 0, ret, 3, Data.Length);
                ret[3 + Data.Length] = (byte)metaLen;
                if (metaLen > 0)
                {
                    Buffer.BlockCopy(ProtocolMetadata, 0, ret, 4 + Data.Length, metaLen);
                }
                ret[4 + Data.Length + metaLen] = SessionId;
            }
            else
            {
                ret = new byte[3 + Data.Length + 1 + metaLen + 1];
                ret[0] = (byte)DestinationNodeId.Id;
                ret[1] = (byte)Data.Length;
                Buffer.BlockCopy(Data, 0, ret, 2, Data.Length);
                ret[2 + Data.Length] = (byte)metaLen;
                if (metaLen > 0)
                {
                    Buffer.BlockCopy(ProtocolMetadata, 0, ret, 3 + Data.Length, metaLen);
                }
                ret[3 + Data.Length + metaLen] = SessionId;
            }
            return ret;
        }

        protected override void OnCallbackInternal(DataReceivedUnit ou)
        {
            // For 0xAC callback, Data is [type, 0xAC, session_id, tx_status, tx_report...].
            // Normalize to FillFromTxReportPayload expected layout [cmd, session_id, tx_status, ...]
            // to avoid mis-detecting tx_status from tx_report bytes.
            var data = ou.DataFrame.Data;
            if (data != null && data.Length > 3)
            {
                var normalized = data.Skip(1).ToArray();
                SpecificResult.FillFromTxReportPayload(normalized);
            }
            "NLS 0xAC callback: SessionId={0}, status={1}, Data.Length={2}, data={3}"._DLOG(
                SessionId, SpecificResult.TransmitStatus, data?.Length ?? 0, data?.GetHex() ?? "");
        }

        public override string AboutMe()
        {
            return $"Data={Data?.GetHex()}; SessionId={SessionId}; {SpecificResult.GetReport()}";
        }

        public SendDataResult SpecificResult => (SendDataResult)Result;

        protected override ActionResult CreateOperationResult()
        {
            return new SendDataResult();
        }
    }
}
