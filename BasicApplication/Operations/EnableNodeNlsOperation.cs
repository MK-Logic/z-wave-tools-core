/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using ZWave.BasicApplication.Enums;
using ZWave.Devices;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Enable Node NLS command (0x6A). Used to enable the state of network layer security (NLS) of an included node.
    /// NLS state cannot be disabled after it has been enabled.
    /// HOST->ZW: REQ | 0x6A | node_id
    /// ZW->HOST: RES | 0x6A | command_status
    /// </summary>
    public class EnableNodeNlsOperation : RequestApiOperation
    {
        public NodeTag NodeId { get; set; }

        public EnableNodeNlsOperation(NetworkViewPoint network, NodeTag nodeId)
            : base(CommandTypes.CmdZWaveEnableNodeNls)
        {
            _network = network;
            NodeId = nodeId;
        }

        protected override byte[] CreateInputParameters()
        {
            if (_network != null && _network.IsNodeIdBaseTypeLR)
            {
                return new byte[] { (byte)(NodeId.Id >> 8), (byte)NodeId.Id };
            }
            return new byte[] { (byte)NodeId.Id };
        }

        protected override void SetStateCompleted(IActionUnit ou)
        {
            var payload = (ou as DataReceivedUnit)?.DataFrame?.Payload;
            if (payload != null && payload.Length > 0)
            {
                SpecificResult.CommandStatus = payload[0];
            }
            base.SetStateCompleted(ou);
        }

        public EnableNodeNlsResult SpecificResult => (EnableNodeNlsResult)Result;

        protected override ActionResult CreateOperationResult()
        {
            return new EnableNodeNlsResult();
        }
    }

    public class EnableNodeNlsResult : ActionResult
    {
        public byte CommandStatus { get; set; }
        public bool IsSuccess => CommandStatus != 0x00;
    }
}
