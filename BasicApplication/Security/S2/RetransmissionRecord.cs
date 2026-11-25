// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Silicon Laboratories Inc. <https://www.silabs.com>
using ZWave.Enums;

namespace ZWave.BasicApplication.Security
{
    public class RetransmissionRecord
    {
        public byte[] Data { get; set; }
        /// <summary>
        /// Group of the MPAN extension that the frame carried, or null. The extension is built again on resend.
        /// </summary>
        public byte? MpanGroupId { get; set; }
        public byte Counter { get; set; }
        public SubstituteSettings SubstituteSettings { get; set; }
        public SecuritySchemes SecurityScheme { get; set; }
        public RetransmissionRecord(byte[] data)
        {
            Data = data;
        }
    }
}
