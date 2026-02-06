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
    /// Sends encrypted protocol (Network Layer) data to the module for RF transmission (0xAC).
    /// HOST->ZW: REQ | 0xAC | destination_node_id | data_length | data[] | protocol_metadata_length | protocol_metadata[] | session_id
    /// ZW->HOST: RES | 0xAC | RetVal
    /// ZW->HOST: REQ | 0xAC | funcID | txStatus | ... (same callback as Send Data)
    /// Used for NLS; only call after receiving <see cref="RequestProtocolCcEncryptionOperation"/> and encrypting the payload.
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
            _network = network;
            DestinationNodeId = destinationNodeId;
            Data = encryptedData ?? Array.Empty<byte>();
            ProtocolMetadata = protocolMetadata ?? Array.Empty<byte>();
            SessionId = sessionId;
        }

        protected override void CreateInstance()
        {
            base.CreateInstance();
            TimeoutMs = SubstituteSettings.CallbackWaitTimeoutMs;
            SpecificResult.TransmitStatus = TransmitStatuses.ResMissing;
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
                    Buffer.BlockCopy(ProtocolMetadata, 0, ret, 4 + Data.Length, metaLen);
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
                    Buffer.BlockCopy(ProtocolMetadata, 0, ret, 3 + Data.Length, metaLen);
                ret[3 + Data.Length + metaLen] = SessionId;
            }
            return ret;
        }

        protected override void OnCallbackInternal(DataReceivedUnit ou)
        {
            var payload = ou.DataFrame.Payload;
            if (payload != null && payload.Length > 1)
            {
                SpecificResult.FuncId = payload[0];
                SpecificResult.TransmitStatus = (TransmitStatuses)payload[1];
                int index = 3;
                if (payload.Length > index)
                {
                    SpecificResult.HasTxTransmitReport = true;
                    SpecificResult.TransmitTicks = (ushort)((payload[index - 1] << 8) + payload[index]);
                    index++;
                    if (payload.Length > index)
                    {
                        SpecificResult.RepeatersCount = payload[index];
                        index++;
                        if (payload.Length > index)
                        {
                            SpecificResult.AckRssi = (sbyte)payload[index];
                            index++;
                            if (payload.Length > index + 3)
                            {
                                SpecificResult.RssiValuesIncoming = new sbyte[] { (sbyte)payload[index], (sbyte)payload[index + 1], (sbyte)payload[index + 2], (sbyte)payload[index + 3] };
                                index += 4;
                            }
                            if (payload.Length > index)
                            {
                                SpecificResult.AckChannelNo = payload[index];
                                index++;
                                if (payload.Length > index)
                                {
                                    SpecificResult.LastTxChannelNo = payload[index];
                                    index++;
                                    if (payload.Length > index)
                                    {
                                        SpecificResult.RouteScheme = (RoutingSchemes)payload[index];
                                        index += 4;
                                        if (payload.Length > index)
                                        {
                                            SpecificResult.Repeaters = new byte[]
                                            {
                                                payload[index - 3],
                                                payload[index - 2],
                                                payload[index - 1],
                                                payload[index]
                                            };
                                            index++;
                                            if (payload.Length > index)
                                            {
                                                SpecificResult.BeamSpeedByte = payload[index];
                                                SpecificResult.RouteSpeed = (byte)(payload[index] & 0x07);
                                                index++;
                                                if (payload.Length > index)
                                                {
                                                    SpecificResult.RouteTries = payload[index];
                                                    index++;
                                                    if (payload.Length > index)
                                                    {
                                                        SpecificResult.LastFailedLinkFrom = payload[index];
                                                        index++;
                                                        if (payload.Length > index)
                                                        {
                                                            SpecificResult.LastFailedLinkTo = payload[index];
                                                            index++;
                                                            if (payload.Length > index)
                                                            {
                                                                SpecificResult.UsedTxpower = (sbyte)payload[index];
                                                                index++;
                                                                if (payload.Length > index)
                                                                {
                                                                    SpecificResult.MeasuredNoiseFloor = (sbyte)payload[index];
                                                                    index++;
                                                                    if (payload.Length > index)
                                                                    {
                                                                        SpecificResult.AckDestinationUsedTxPower = (sbyte)payload[index];
                                                                        index++;
                                                                        if (payload.Length > index)
                                                                        {
                                                                            SpecificResult.DestinationAckMeasuredRSSI = (sbyte)payload[index];
                                                                            index++;
                                                                            if (payload.Length > index)
                                                                            {
                                                                                SpecificResult.DestinationckMeasuredNoiseFloor = (sbyte)payload[index];
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
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
