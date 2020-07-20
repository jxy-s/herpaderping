//
// Copyright (c) Johnny Shaw. All rights reserved.
// 
// File:     source/ProcessHerpaderping/herpaderp.hpp
// Author:   Johnny Shaw
// Abstract: Herpaderping Functionality
//
#pragma once

namespace Herpaderp
{

    /// <summary>
    /// Executes process herpaderping.
    /// </summary>
    /// <param name="TargetBinary">
    /// Target binary to execute.
    /// </param>
    /// <param name="FileName">
    /// File name to copy target to and obfuscate.
    /// </param>
    /// <param name="ReplaceWith">
    /// Optional, if provided the file is replaced with the content of this 
    /// file. If not provided the file is overwritten with a pattern.
    /// </param>
    /// <param name="Pattern">
    /// Pattern used for obfuscation.
    /// </param>
    /// <param name="WaitForProcess">
    /// If true, function waits for the herpaderped process to exit.
    /// </param>
    /// <param name="HoldHandleExclusive">
    /// If true, the function creates the target file with exclusive access 
    /// and holds the handle open longer.
    /// </param>
    /// <returns>
    /// Success if the herpaderping executed. Failure otherwise.
    /// </returns>
    _Must_inspect_result_ HRESULT ExecuteProcess(
        _In_ const std::wstring& TargetBinary,
        _In_ const std::wstring& FileName,
        _In_opt_ const std::optional<std::wstring>& ReplaceWith,
        _In_ std::span<const uint8_t> Pattern, 
        _In_ bool WaitForProcess,
        _In_ bool HoldHandleExclusive);

}
