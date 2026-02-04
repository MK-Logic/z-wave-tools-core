/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using System;
using ZWave.BasicApplication.Enums;
using ZWave.Devices;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Transfers a decrypted protocol (Network Layer) command from host to module (0x69).
    /// HOST->ZW: REQ | 0x69 | src_node_id | decryption_key | payload_length | payload[]
    /// ZW->HOST: RES | 0x69 | RetVal
    /// Used when host has decrypted an incoming NLS frame and the inner command is a Network Layer CC
    /// (Z-Wave Protocol CC 0x01 / Z-Wave Long Range CC 0x04).
    /// </summary>
    public class TransferProtocolCcOperation : RequestApiOperation
    {
        public NodeTag SrcNode { get; set; }
        public byte DecryptionKey { get; set; }
        public byte[] Payload { get; set; }

        public TransferProtocolCcOperation(NetworkViewPoint network, NodeTag srcNode, byte decryptionKey, byte[] payload)
            : base(CommandTypes.CmdZWaveTransferProtocolCc)
        {
            _network = network;
            SrcNode = srcNode;
            DecryptionKey = decryptionKey;
            Payload = payload ?? Array.Empty<byte>();
        }

        protected override byte[] CreateInputParameters()
        {
            byte[] ret;
            if (_network.IsNodeIdBaseTypeLR)
            {
                ret = new byte[4 + Payload.Length];
                ret[0] = (byte)(SrcNode.Id >> 8);
                ret[1] = (byte)SrcNode.Id;
                ret[2] = DecryptionKey;
                ret[3] = (byte)Payload.Length;
                Buffer.BlockCopy(Payload, 0, ret, 4, Payload.Length);
            }
            else
            {
                ret = new byte[3 + Payload.Length];
                ret[0] = (byte)SrcNode.Id;
                ret[1] = DecryptionKey;
                ret[2] = (byte)Payload.Length;
                Buffer.BlockCopy(Payload, 0, ret, 3, Payload.Length);
            }
            return ret;
        }
    }
}
