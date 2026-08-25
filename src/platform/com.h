// Copyright © 2026 Racpast. All Rights Reserved.
//
// This file is part of SNIBypassGUI, a proprietary software project.
//
// NOTICE: All information contained herein is, and remains the property of
// Racpast. The intellectual and technical concepts contained herein are
// proprietary to Racpast and are protected by copyright law and international
// treaties. Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained from Racpast.
//
// Unauthorized copying, modification, distribution, or use of this file,
// via any medium, is strictly prohibited.
//
// For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com
//
// See the LICENSE file in the project root for full terms and conditions.

#pragma once
#include <objbase.h>
#include <oleauto.h>

#include <string>

// The minimum COM plumbing this program needs. Two subsystems talk to COM — the
// desktop shortcut (IShellLink) and autostart (ITaskService) — and both would
// otherwise repeat the same apartment bookkeeping and the same hand-written
// Release/SysFreeString paths, where one early return is all it takes to leak.
namespace Com {

// Initializes COM for the calling thread and undoes it on scope exit.
//
// A thread that already has an apartment gets S_FALSE, which still increments the
// initialization count and therefore still has to be balanced; only
// RPC_E_CHANGED_MODE (a different apartment model is already in force) is a
// failure we must not balance. SUCCEEDED() draws exactly that line.
class Scope {
public:
    Scope()
        : owned_(SUCCEEDED(
              CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))) {}
    ~Scope() {
        if (owned_) CoUninitialize();
    }
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

private:
    const bool owned_;
};

// Owning interface pointer.
template <typename T>
class Ptr {
public:
    Ptr() = default;
    ~Ptr() { Reset(); }

    Ptr(Ptr&& other) noexcept : ptr_(other.ptr_) { other.ptr_ = nullptr; }
    Ptr& operator=(Ptr&& other) noexcept {
        if (this != &other) {
            Reset();
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }
    Ptr(const Ptr&) = delete;
    Ptr& operator=(const Ptr&) = delete;

    // Out-parameter for a call that returns a new reference.
    T** Put() {
        Reset();
        return &ptr_;
    }
    void** PutVoid() {
        Reset();
        return reinterpret_cast<void**>(&ptr_);
    }

    T* operator->() const { return ptr_; }
    T* Get() const { return ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }

    void Reset() {
        if (ptr_) {
            ptr_->Release();
            ptr_ = nullptr;
        }
    }

private:
    T* ptr_ = nullptr;
};

// Owning BSTR.
class Bstr {
public:
    Bstr() = default;
    explicit Bstr(const wchar_t* text) : value_(SysAllocString(text)) {}
    explicit Bstr(const std::wstring& text) : Bstr(text.c_str()) {}
    ~Bstr() { Reset(); }

    Bstr(Bstr&& other) noexcept : value_(other.value_) { other.value_ = nullptr; }
    Bstr& operator=(Bstr&& other) noexcept {
        if (this != &other) {
            Reset();
            value_ = other.value_;
            other.value_ = nullptr;
        }
        return *this;
    }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;

    BSTR* Put() {
        Reset();
        return &value_;
    }
    BSTR Get() const { return value_; }
    explicit operator bool() const { return value_ != nullptr; }
    std::wstring Str() const {
        return value_ ? std::wstring(value_, SysStringLen(value_)) : std::wstring();
    }

    void Reset() {
        if (value_) {
            SysFreeString(value_);
            value_ = nullptr;
        }
    }

private:
    BSTR value_ = nullptr;
};

// An empty VARIANT, cleaned up on scope exit. Task Scheduler takes several of
// these by value for arguments it does not need.
class Variant {
public:
    Variant() { VariantInit(&value_); }
    ~Variant() { VariantClear(&value_); }
    Variant(const Variant&) = delete;
    Variant& operator=(const Variant&) = delete;

    VARIANT& Get() { return value_; }

private:
    VARIANT value_;
};

}  // namespace Com
