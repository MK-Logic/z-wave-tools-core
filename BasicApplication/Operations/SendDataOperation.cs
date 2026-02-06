/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Silicon Laboratories Inc. https://www.silabs.com
using System;
using ZWave.Enums;
using ZWave.BasicApplication.Enums;
using Utils;
using ZWave.Devices;
using System.Linq;

namespace ZWave.BasicApplication.Operations
{
    public class SendDataOperation : CallbackApiOperation, ISendDataAction
    {
        public NodeTag DstNode { get; set; }
        internal NodeTag SrcNode { get; set; }
        public byte[] Data { get; set; }
        internal bool IsFollowup { get; set; }
        internal TransmitOptions TxOptions { get; private set; }
        public Action SubstituteCallback { get; set; }
        public object Extensions { get; set; }

        public SendDataOperation(NetworkViewPoint network, NodeTag node, byte[] data, TransmitOptions txOptions)
            : this(network, NodeTag.Empty, node, data, txOptions)
        { }

        public SendDataOperation(NetworkViewPoint network, NodeTag srcNode, NodeTag dstNode, byte[] data, TransmitOptions txOptions)
            : base(CommandTypes.CmdZWaveSendData, CommandTypes.CmdZWaveSendDataAbort)
        {
            _network = network;
            SrcNode = srcNode;
            DstNode = dstNode;
            Data = data;
            TxOptions = txOptions;
        }

        private ApiMessage messageSendDataAbort;

        protected override void CreateWorkflow()
        {
            base.CreateWorkflow();
            StopActionUnit = new StopActionUnit(messageSendDataAbort);
        }

        protected override void CreateInstance()
        {
            base.CreateInstance();
            TimeoutMs = SubstituteSettings.CallbackWaitTimeoutMs;
            SpecificResult.TransmitStatus = TransmitStatuses.ResMissing;
            messageSendDataAbort = new ApiMessage(CommandTypes.CmdZWaveSendDataAbort);
        }

        protected override byte[] CreateInputParameters()
        {
            if (Data == null)
            {
                Data = new byte[0];
            }
            byte[] ret = new byte[3 + Data.Length];
            ret[0] = (byte)DstNode.Id;
            ret[1] = (byte)Data.Length;
            for (int i = 0; i < Data.Length; i++)
            {
                ret[i + 2] = Data[i];
            }
            ret[2 + Data.Length] = (byte)TxOptions;
            if (_network.IsNodeIdBaseTypeLR)
            {
                ret = new byte[4 + Data.Length];
                ret[0] = (byte)(DstNode.Id >> 8);
                ret[1] = (byte)DstNode.Id;
                ret[2] = (byte)Data.Length;
                for (int i = 0; i < Data.Length; i++)
                {
                    ret[i + 3] = Data[i];
                }
                ret[3 + Data.Length] = (byte)TxOptions;
            }
            return ret;
        }

        protected override void OnHandled(DataReceivedUnit ou)
        {
            if (SubstituteSettings.IsSkipWaitingSendCallbackEnabled)
            {
                SetStateCompleted(ou);
            }
        }

        protected override void OnCallbackInternal(DataReceivedUnit ou)
        {
            var payload = ou.DataFrame.Payload;
            if (payload != null && payload.Length > 1)
            {
                SpecificResult.FillFromTxReportPayload(payload);
            }
        }

        public override string AboutMe()
        {
            return $"Data={Data.GetHex()}; {SpecificResult.GetReport()}";
        }

        public SendDataResult SpecificResult
        {
            get { return (SendDataResult)Result; }
        }

        protected override ActionResult CreateOperationResult()
        {
            return new SendDataResult();
        }
    }

    public class TransmitResult : ActionResult
    {
        public byte FuncId { get; set; }
        public TransmitStatuses TransmitStatus { get; set; }
    }

    public class SendDataResult : TransmitResult
    {
        public bool HasTxTransmitReport { get; set; }
        public ushort TransmitTicks { get; set; }
        public byte RepeatersCount { get; set; }
        /// <summary>RSSI of the ACK frame (Controller Node Send Protocol Data (0xAC) / NLS TX report byte 5).</summary>
        public sbyte AckRssi { get; set; }
        public sbyte[] RssiValuesIncoming { get; set; }
        public byte AckChannelNo { get; set; }
        public byte LastTxChannelNo { get; set; }
        public RoutingSchemes RouteScheme { get; set; }
        public byte[] Repeaters { get; set; }
        /// <summary>Combined beam/speed byte (beam_1000ms bit6, beam_250ms bit5, last_route_speed bits 0-2). Used for Request Protocol CC Encryption (0x6C) callback.</summary>
        public byte BeamSpeedByte { get; set; }
        public byte RouteSpeed { get; set; }
        public byte RouteTries { get; set; }
        public byte LastFailedLinkFrom { get; set; }
        public byte LastFailedLinkTo { get; set; }
        public sbyte UsedTxpower { get; set; }
        public sbyte MeasuredNoiseFloor { get; set; }
        public sbyte AckDestinationUsedTxPower { get; set; }
        public sbyte DestinationAckMeasuredRSSI { get; set; }
        public sbyte DestinationckMeasuredNoiseFloor { get; set; }
        public SubstituteStatuses TxSubstituteStatus { get; set; }

        /// <summary>
        /// Fills this result from the callback payload per Z-Wave Host API spec (CSWG),
        /// with a fallback for older callback layouts that omit the Session identifier.
        /// CSWG layout: [0]Z-Wave API Command ID, [1]Session identifier, [2]Tx Status, [3..]Tx Status Report.
        /// Legacy layout: [0]Z-Wave API Command ID, [1]Tx Status, [2..]Tx Status Report.
        /// Tx Status Report: [0-1]Transmit Ticks, [2]Number of repeaters, [3]Ack RSSI, [4-7]RSSI Repeater 0-3,
        /// [8]ACK Channel No, [9]Tx Channel No, [10]Route Scheme, [11-14]Last Route Repeater 0-3, [15]beam/speed,
        /// [16]Routing Attempts, [17-18]Last failed link from/to, [19]Tx Power, [20]Noise Floor, [21-23]Destination Ack....
        /// </summary>
        public void FillFromTxReportPayload(byte[] payload)
        {
            if (payload == null || payload.Length < 2)
            {
                return;
            }
            FuncId = payload[0];
            int txStatusIndex = 1;
            if (payload.Length > 2 && IsValidTransmitStatus(payload[2]))
            {
                txStatusIndex = 2;
            }
            TransmitStatus = (TransmitStatuses)payload[txStatusIndex];
            int reportStartIndex = txStatusIndex + 1;
            if (payload.Length <= reportStartIndex + 1)
            {
                return;
            }
            HasTxTransmitReport = true;
            TransmitTicks = (ushort)((payload[reportStartIndex] << 8) | payload[reportStartIndex + 1]);
            if (payload.Length <= reportStartIndex + 2)
            {
                return;
            }
            RepeatersCount = payload[reportStartIndex + 2];
            AckRssi = (sbyte)payload[reportStartIndex + 3];
            if (payload.Length <= reportStartIndex + 7)
            {
                return;
            }
            RssiValuesIncoming = new sbyte[]
            {
                (sbyte)payload[reportStartIndex + 4],
                (sbyte)payload[reportStartIndex + 5],
                (sbyte)payload[reportStartIndex + 6],
                (sbyte)payload[reportStartIndex + 7]
            };
            AckChannelNo = payload[reportStartIndex + 8];
            if (payload.Length <= reportStartIndex + 10)
            {
                return;
            }
            LastTxChannelNo = payload[reportStartIndex + 9];
            RouteScheme = (RoutingSchemes)payload[reportStartIndex + 10];
            if (payload.Length <= reportStartIndex + 15)
            {
                return;
            }
            Repeaters = new byte[]
            {
                payload[reportStartIndex + 11],
                payload[reportStartIndex + 12],
                payload[reportStartIndex + 13],
                payload[reportStartIndex + 14]
            };
            BeamSpeedByte = payload[reportStartIndex + 15];
            RouteSpeed = (byte)(payload[reportStartIndex + 15] & 0x07);
            if (payload.Length <= reportStartIndex + 16)
            {
                return;
            }
            RouteTries = payload[reportStartIndex + 16];
            if (payload.Length <= reportStartIndex + 18)
            {
                return;
            }
            LastFailedLinkFrom = payload[reportStartIndex + 17];
            LastFailedLinkTo = payload[reportStartIndex + 18];
            if (payload.Length <= reportStartIndex + 19)
            {
                return;
            }
            UsedTxpower = (sbyte)payload[reportStartIndex + 19];
            if (payload.Length <= reportStartIndex + 21)
            {
                return;
            }
            MeasuredNoiseFloor = (sbyte)payload[reportStartIndex + 20];
            AckDestinationUsedTxPower = (sbyte)payload[reportStartIndex + 21];
            if (payload.Length <= reportStartIndex + 23)
            {
                return;
            }
            DestinationAckMeasuredRSSI = (sbyte)payload[reportStartIndex + 22];
            DestinationckMeasuredNoiseFloor = (sbyte)payload[reportStartIndex + 23];
        }

        private static bool IsValidTransmitStatus(byte status)
        {
            return status == (byte)TransmitStatuses.CompleteOk
                || status == (byte)TransmitStatuses.CompleteNoAcknowledge
                || status == (byte)TransmitStatuses.CompleteFail
                || status == (byte)TransmitStatuses.RoutingNotIdle
                || status == (byte)TransmitStatuses.CompleteNoRoute
                || status == (byte)TransmitStatuses.CompleteVerified
                || status == (byte)TransmitStatuses.ResMissing;
        }

        public void CopyFrom(SendDataResult result)
        {
            if (result != null)
            {
                TransmitStatus = result.TransmitStatus;
                HasTxTransmitReport = result.HasTxTransmitReport;
                TransmitTicks = result.TransmitTicks;
                RepeatersCount = result.RepeatersCount;
                AckRssi = result.AckRssi;
                RssiValuesIncoming = result.RssiValuesIncoming;
                AckChannelNo = result.AckChannelNo;
                LastTxChannelNo = result.LastTxChannelNo;
                RouteScheme = result.RouteScheme;
                Repeaters = result.Repeaters;
                BeamSpeedByte = result.BeamSpeedByte;
                RouteSpeed = result.RouteSpeed;
                RouteTries = result.RouteTries;
                LastFailedLinkFrom = result.LastFailedLinkFrom;
                LastFailedLinkTo = result.LastFailedLinkTo;
                UsedTxpower = result.UsedTxpower;
                MeasuredNoiseFloor = result.MeasuredNoiseFloor;
                AckDestinationUsedTxPower = result.AckDestinationUsedTxPower;
                DestinationAckMeasuredRSSI = result.DestinationAckMeasuredRSSI;
                DestinationckMeasuredNoiseFloor = result.DestinationckMeasuredNoiseFloor;
                TxSubstituteStatus = result.TxSubstituteStatus;
            }
        }

        public void AggregateWith(SendDataResult result)
        {
            if (result != null)
            {
                HasTxTransmitReport = result.HasTxTransmitReport;
                TransmitTicks += result.TransmitTicks;
                RepeatersCount = result.RepeatersCount;
                AckRssi = result.AckRssi;
                RssiValuesIncoming = result.RssiValuesIncoming;
                AckChannelNo = result.AckChannelNo;
                LastTxChannelNo = result.LastTxChannelNo;
                RouteScheme = result.RouteScheme;
                Repeaters = result.Repeaters;
                BeamSpeedByte = result.BeamSpeedByte;
                RouteSpeed = result.RouteSpeed;
                RouteTries += result.RouteTries;
                LastFailedLinkFrom = result.LastFailedLinkFrom;
                LastFailedLinkTo = result.LastFailedLinkTo;
                UsedTxpower = result.UsedTxpower;
                MeasuredNoiseFloor = result.MeasuredNoiseFloor;
                AckDestinationUsedTxPower = result.AckDestinationUsedTxPower;
                DestinationAckMeasuredRSSI = result.DestinationAckMeasuredRSSI;
                DestinationckMeasuredNoiseFloor = result.DestinationckMeasuredNoiseFloor;
                TxSubstituteStatus = result.TxSubstituteStatus;
            }
        }

        public string GetReport()
        {
            return $"{TransmitStatus} (Tr={RouteTries} RSc=0x{((byte)RouteScheme):X2} RSp=0x{RouteSpeed:X2}" 
                + (Repeaters != null && Repeaters.Length > 0 && Repeaters.Any(x => x > 0) ? $" Rpt={Repeaters.TakeWhile(x => x > 0).GetHex()}" : $"")
                + (RssiValuesIncoming!= null && RssiValuesIncoming.Length > 0 ? $" TPw={UsedTxpower} Rs0={RssiValuesIncoming[0]}" : $"")
                + ")";
        }
    }
}
