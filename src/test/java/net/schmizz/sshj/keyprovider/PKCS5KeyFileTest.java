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

import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.PKCS5KeyFile;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
import net.schmizz.sshj.util.KeyUtil;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;

public class PKCS5KeyFileTest {

    static final FileKeyProvider rsa = new PKCS5KeyFile();

    static final String modulus = "";
    static final String pubExp = "23";
    static final String privExp = "";

    final char[] correctPassphrase = "passphrase".toCharArray();
    final char[] incorrectPassphrase = "incorrect".toCharArray();

    @Before
    public void setUp()
            throws UnsupportedEncodingException, GeneralSecurityException {
        rsa.init(new File("src/test/resources/id_rsa"));
    }

    @Test
    public void testKeys()
            throws IOException, GeneralSecurityException {
        assertEquals(KeyUtil.newRSAPublicKey(modulus, pubExp), rsa.getPublic());
        assertEquals(KeyUtil.newRSAPrivateKey(modulus, privExp), rsa.getPrivate());
    }

    @Test
    public void testType()
            throws IOException {
        assertEquals(rsa.getType(), KeyType.RSA);
    }

    final PasswordFinder givesOn3rdTry = new PasswordFinder() {
        int triesLeft = 3;

        @Override
        public char[] reqPassword(Resource resource) {
            if (triesLeft == 0)
                return correctPassphrase;
            else {
                triesLeft--;
                return incorrectPassphrase;
            }
        }

        @Override
        public boolean shouldRetry(Resource resource) {
            return triesLeft >= 0;
        }
    };

    @Test
    public void retries()
            throws IOException, GeneralSecurityException {
        FileKeyProvider rsa = new PKCS5KeyFile();
        rsa.init(new File("src/test/resources/rsa.pk5"), givesOn3rdTry);
        assertEquals(KeyUtil.newRSAPublicKey(modulus, pubExp), rsa.getPublic());
        assertEquals(KeyUtil.newRSAPrivateKey(modulus, privExp), rsa.getPrivate());
    }
}
