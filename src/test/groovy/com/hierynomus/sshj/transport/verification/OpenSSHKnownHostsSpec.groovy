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
package com.hierynomus.sshj.transport.verification

import net.schmizz.sshj.common.Base64
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts
import net.schmizz.sshj.util.KeyUtil
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import spock.lang.Specification
import spock.lang.Unroll

import java.security.PublicKey

class OpenSSHKnownHostsSpec extends Specification {

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    def "should parse and verify hashed host entry"() {
        given:
        def f = knownHosts("");
        final PublicKey key = KeyUtil
                .newRSAPublicKey(
                "",
                "23");

        when:
        OpenSSHKnownHosts openSSHKnownHosts = new OpenSSHKnownHosts(f)

        then:
        openSSHKnownHosts.verify("192.168.1.61", 22, key)
        !openSSHKnownHosts.verify("192.168.1.2", 22, key)
    }

    def "should parse and verify v1 host entry"() {
        given:
        def f = knownHosts("")
        def key = KeyUtil.newRSAPublicKey("",
                    "23")
        when:
        OpenSSHKnownHosts knownHosts = new OpenSSHKnownHosts(f)

        then:
        knownHosts.verify("test.com", 22, key)
    }

    def "should check all host entries for key"() {
        given:
        def f = knownHosts("""
""")
        def pk = new Buffer.PlainBuffer(Base64.decode("")).readPublicKey()
        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        then:
        knownhosts.verify("host1", 22, pk)
    }

    def "should not fail on bad base64 entry"() {
        given:
        def f = knownHosts("""
""")
        def pk = new Buffer.PlainBuffer(Base64.decode("")).readPublicKey()
        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        then:
        knownhosts.verify("host1", 22, pk)
    }

    def "should mark bad line and not fail"() {
        given:
        def f = knownHosts("")

        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        then:
        knownhosts.entries().size() == 1
        knownhosts.entries().get(0) instanceof OpenSSHKnownHosts.BadHostEntry
    }

    @Unroll
    def "should add comment for #type line"() {
        given:
        def f = knownHosts(s)

        when:
        def knownHosts = new OpenSSHKnownHosts(f)

        then:
        knownHosts.entries().size() == 1
        knownHosts.entries().get(0) instanceof OpenSSHKnownHosts.CommentEntry

        where:
        type << ["newline", "comment"]
        s << ["\n", "#comment\n"]
    }

    @Unroll
    def "should match any host name from multi-host line"() {
        given:
        def f = knownHosts("")
        def pk = new Buffer.PlainBuffer(Base64.decode("")).readPublicKey()

        when:
        def knownHosts = new OpenSSHKnownHosts(f)

        then:
        knownHosts.verify(h, 22, pk)

        where:
        h << ["schmizz.net", "69.163.155.180"]
    }

    def "should produce meaningful toString()"() {
        given:
        def f = knownHosts("")

        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        def toStringValue = knownhosts.toString()
        then:
        toStringValue == "OpenSSHKnownHosts{khFile='" + f + "'}"
    }

    def "should forgive redundant spaces like OpenSSH does"() {
        given:
        def key = ""
        def f = knownHosts("""
          |host1 ssh-ed25519 $key
          |
          | host2   ssh-ed25519   $key  ,./gargage\\.,
          |\t\t\t\t\t
          |\t@revoked   host3\tssh-ed25519\t \t$key\t
          """.stripMargin())
        def pk = new Buffer.PlainBuffer(Base64.decode(key)).readPublicKey()

        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        then:
        ["host1", "host2", "host3"].forEach {
            knownhosts.verify(it, 22, pk)
        }
    }

    def "should not throw errors while parsing corrupted records"() {
        given:
        def key = ""
        def f = knownHosts(
                "\n"  // empty line
                + "    \n"  // blank line
                + "bad-host1\n"  // absent key type and key contents
                + "bad-host2 ssh-ed25519\n"  // absent key contents
                + "  bad-host3 ssh-ed25519\n"  // absent key contents, with leading spaces
                + "@revoked  bad-host5 ssh-ed25519\n"  // absent key contents, with marker
                + "good-host ssh-ed25519 $key"  // the only good host at the end
        )

        when:
        def knownhosts = new OpenSSHKnownHosts(f)

        then:
        knownhosts.verify("good-host", 22, new Buffer.PlainBuffer(Base64.decode(key)).readPublicKey())
    }

    def knownHosts(String s) {
        def f = temp.newFile("known_hosts")
        f.write(s)
        return f
    }
}
