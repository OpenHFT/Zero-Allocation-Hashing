/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
module net.openhft.it.module {
    requires net.openhft.hashing;
    requires junit;
    exports net.openhft.it.module;
    opens net.openhft.it.module to junit;
}
