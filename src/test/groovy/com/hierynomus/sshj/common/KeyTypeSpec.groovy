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
package com.hierynomus.sshj.common

import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile
import spock.lang.Specification
import spock.lang.Unroll

class KeyTypeSpec extends Specification {

    @Unroll
    def "should determine correct keytype for #type key"() {
        given:
        OpenSSHKeyFile kf = new OpenSSHKeyFile()
        kf.init(privKey, pubKey)

        expect:
        KeyType.fromKey(kf.getPublic()) == type
        KeyType.fromKey(kf.getPrivate()) == type

        where:
        privKey << ["""-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----"""]
        pubKey << [""""""]
        type << [KeyType.ECDSA256]

    }
}
