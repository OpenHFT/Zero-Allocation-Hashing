/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
//! Publish an explicit module with only the public hashing package exported.
//! ModuleTest#testExplicitDescriptorContract rejects an automatic module or extra exports;
//! #testPublicAPIAccessible checks consumers can still call the API.
module net.openhft.hashing {
    //! Unsafe remains a runtime dependency of existing hashing paths, not an optional annotation.
    //! ModuleTest#testExplicitDescriptorContract requires a non-static jdk.unsupported edge;
    //! #testPublicRuntimePathsWithRequiredDirectBufferExport exercises those paths.
    requires jdk.unsupported;
    //! Declare compile-time annotations without forcing ordinary runtime consumers to install them.
    //! ModuleTest#testExplicitDescriptorContract requires the STATIC jsr305 dependency.
    requires static jsr305;
    exports net.openhft.hashing;
}
