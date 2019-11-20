/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.schmizz.sshj.keyprovider;

import net.schmizz.sshj.userauth.keyprovider.PuTTYKeyFile;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
import org.junit.Test;

import java.io.IOException;
import java.io.StringReader;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class PuTTYKeyFileTest {

    @Test
    public void test2048() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk2048));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void test4096() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk4096));
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test
    public void testCorrectPassphraseRsa() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk1024_passphrase), new PasswordFinder() {
            @Override
            public char[] reqPassword(Resource<?> resource) {
                // correct passphrase
                return "123456".toCharArray();
            }

            @Override
            public boolean shouldRetry(Resource<?> resource) {
                return false;
            }
        });
        // Install JCE Unlimited Strength Jurisdiction Policy Files if we get java.security.InvalidKeyException: Illegal key size
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test(expected = IOException.class)
    public void testWrongPassphraseRsa() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppk1024_passphrase), new PasswordFinder() {
            @Override
            public char[] reqPassword(Resource<?> resource) {
                // wrong passphrase
                return "egfsdgdfgsdfsdfasfs523534dgdsgdfa".toCharArray();
            }

            @Override
            public boolean shouldRetry(Resource<?> resource) {
                return false;
            }
        });
        assertNotNull(key.getPublic());
        assertNull(key.getPrivate());
    }

    @Test
    public void testCorrectPassphraseDsa() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppkdsa_passphrase), new PasswordFinder() {
            @Override
            public char[] reqPassword(Resource<?> resource) {
                // correct passphrase
                return "secret".toCharArray();
            }

            @Override
            public boolean shouldRetry(Resource<?> resource) {
                return false;
            }
        });
        // Install JCE Unlimited Strength Jurisdiction Policy Files if we get java.security.InvalidKeyException: Illegal key size
        assertNotNull(key.getPrivate());
        assertNotNull(key.getPublic());
    }

    @Test(expected = IOException.class)
    public void testWrongPassphraseDsa() throws Exception {
        PuTTYKeyFile key = new PuTTYKeyFile();
        key.init(new StringReader(ppkdsa_passphrase), new PasswordFinder() {
            @Override
            public char[] reqPassword(Resource<?> resource) {
                // wrong passphrase
                return "egfsdgdfgsdfsdfasfs523534dgdsgdfa".toCharArray();
            }

            @Override
            public boolean shouldRetry(Resource<?> resource) {
                return false;
            }
        });
        assertNotNull(key.getPublic());
        assertNull(key.getPrivate());
    }
}
