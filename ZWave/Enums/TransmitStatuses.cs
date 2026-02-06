/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Silicon Laboratories Inc. https://www.silabs.com
namespace ZWave.Enums
{
    /// <summary>
    /// Transmit Statuses enumeration.
    /// </summary>
    public enum TransmitStatuses
    {
        /// <summary>
        /// Successfully
        /// </summary>
        CompleteOk = 0x00,
        /// <summary>
        /// No acknowledge is received before timeout from the destination node. 
        /// Acknowledge is discarded in case it is received after the timeout.
        /// </summary>
        CompleteNoAcknowledge = 0x01,
        /// <summary>
        /// Not possible to transmit data because the Z-Wave network is busy (jammed).
        /// </summary>
        CompleteFail = 0x02,
        /// <summary>
        /// Transmission failed due to routing being locked/busy.
        /// </summary>
        RoutingNotIdle = 0x03,
        /// <summary>
        /// No route found in Assign Route.
        /// </summary>
        CompleteNoRoute = 0x04,
        /// <summary>
        /// Transmission completed and successful, including S2 resynchronization back-off.
        /// </summary>
        CompleteVerified = 0x05,
        /// <summary>
        /// Backwards compatibility: same as CompleteNoAcknowledge (0x01). Do not use for new code.
        /// (Historically this member was 0x05, which was incorrect per CSWG; 0x05 is now CompleteVerified.)
        /// </summary>
        NoAcknowledge = CompleteNoAcknowledge,
        /// <summary>
        /// No response received.
        /// </summary>
        ResMissing = 0x06
    }
}
