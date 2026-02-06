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
                Data = new byte[0];
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
                SpecificResult.FillFromTxReportPayload(payload);
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
        /// Fills this result from the standard TX report payload layout (Send Data / Controller Node Send Protocol Data (0xAC) callback).
        /// Layout: [0]FuncId, [1]TxStatus, [2-3]TransmitTicks, [4]RepeatersCount, [5]AckRssi, [6-9]Rssi×4,
        /// [10]AckChannelNo, [11]LastTxChannelNo, [12]RouteScheme, [13-16]Repeaters×4, [17]BeamSpeedByte,
        /// [18]RouteTries, [19]LastFailedLinkFrom, [20]LastFailedLinkTo, [21]UsedTxpower, [22]MeasuredNoiseFloor,
        /// [23]AckDestinationUsedTxPower, [24]DestinationAckMeasuredRSSI, [25]DestinationckMeasuredNoiseFloor.
        /// </summary>
        public void FillFromTxReportPayload(byte[] payload)
        {
            if (payload == null || payload.Length < 2)
                return;
            FuncId = payload[0];
            TransmitStatus = (TransmitStatuses)payload[1];
            if (payload.Length <= 3)
                return;
            HasTxTransmitReport = true;
            TransmitTicks = (ushort)((payload[2] << 8) | payload[3]);
            if (payload.Length <= 4)
                return;
            RepeatersCount = payload[4];
            if (payload.Length <= 5)
                return;
            AckRssi = (sbyte)payload[5];
            if (payload.Length <= 9)
                return;
            RssiValuesIncoming = new sbyte[] { (sbyte)payload[6], (sbyte)payload[7], (sbyte)payload[8], (sbyte)payload[9] };
            if (payload.Length <= 10)
                return;
            AckChannelNo = payload[10];
            if (payload.Length <= 11)
                return;
            LastTxChannelNo = payload[11];
            if (payload.Length <= 12)
                return;
            RouteScheme = (RoutingSchemes)payload[12];
            if (payload.Length <= 16)
                return;
            Repeaters = new byte[] { payload[13], payload[14], payload[15], payload[16] };
            if (payload.Length <= 17)
                return;
            BeamSpeedByte = payload[17];
            RouteSpeed = (byte)(payload[17] & 0x07);
            if (payload.Length <= 18)
                return;
            RouteTries = payload[18];
            if (payload.Length <= 19)
                return;
            LastFailedLinkFrom = payload[19];
            if (payload.Length <= 20)
                return;
            LastFailedLinkTo = payload[20];
            if (payload.Length <= 21)
                return;
            UsedTxpower = (sbyte)payload[21];
            if (payload.Length <= 22)
                return;
            MeasuredNoiseFloor = (sbyte)payload[22];
            if (payload.Length <= 23)
                return;
            AckDestinationUsedTxPower = (sbyte)payload[23];
            if (payload.Length <= 24)
                return;
            DestinationAckMeasuredRSSI = (sbyte)payload[24];
            if (payload.Length <= 25)
                return;
            DestinationckMeasuredNoiseFloor = (sbyte)payload[25];
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
