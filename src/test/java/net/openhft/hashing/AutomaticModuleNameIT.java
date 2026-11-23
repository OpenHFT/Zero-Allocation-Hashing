/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AutomaticModuleNameIT {

    private static final String EXPECTED_MODULE_NAME = "net.openhft.hashing";

    @Test
    public void packagedJarDeclaresAutomaticModuleName() throws IOException {
        final String packagedJarPath = System.getProperty("packaged.jar");
        assertNotNull("packaged.jar system property", packagedJarPath);

        final File packagedJar = new File(packagedJarPath);
        assertTrue("Packaged JAR does not exist: " + packagedJar, packagedJar.isFile());

        try (JarFile jarFile = new JarFile(packagedJar)) {
            final Manifest manifest = jarFile.getManifest();
            assertNotNull("Packaged JAR has no manifest: " + packagedJar, manifest);
            final Attributes attributes = manifest.getMainAttributes();
            assertEquals(EXPECTED_MODULE_NAME, attributes.getValue("Automatic-Module-Name"));
        }
    }
}
