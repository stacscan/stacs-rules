/**
 *
 * Taken from sshpubk.c of the PuTTY source:
 *
 *     PuTTY is copyright 1997-2020 Simon Tatham.
 *     
 *     Portions copyright Robert de Bath, Joris van Rantwijk, Delian
 *     Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas Barry,
 *     Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus
 *     Kuhn, Colin Watson, Christopher Staite, Lorenz Diener, Christian
 *     Brabandt, Jeff Smith, Pavel Kryukov, Maxim Kuznetsov, Svyatoslav
 *     Kuzmich, Nico Williams, Viktor Dukhovni, Josh Dersch, Lars Brinkhoff,
 *     and CORE SDI S.A.
 *     
 *     Permission is hereby granted, free of charge, to any person
 *     obtaining a copy of this software and associated documentation files
 *     (the "Software"), to deal in the Software without restriction,
 *     including without limitation the rights to use, copy, modify, merge,
 *     publish, distribute, sublicense, and/or sell copies of the Software,
 *     and to permit persons to whom the Software is furnished to do so,
 *     subject to the following conditions:
 *     
 *     The above copyright notice and this permission notice shall be
 *     included in all copies or substantial portions of the Software.
 *     
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE
 *     FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 *     CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *     WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

/*
 * PuTTY's own format for SSH-2 keys is as follows:
 *
 * The file is text. Lines are terminated by LF by preference,
 * although CRLF and CR-only are tolerated on input.
 *
 * The first line says "PuTTY-User-Key-File-2: " plus the name of the
 * algorithm ("ssh-dss", "ssh-rsa" etc).
 *
 * The next line says "Encryption: " plus an encryption type.
 * Currently the only supported encryption types are "aes256-cbc"
 * and "none".
 *
 * The next line says "Comment: " plus the comment string.
 *
 * Next there is a line saying "Public-Lines: " plus a number N.
 * The following N lines contain a base64 encoding of the public
 * part of the key. This is encoded as the standard SSH-2 public key
 * blob (with no initial length): so for RSA, for example, it will
 * read
 *
 *    string "ssh-rsa"
 *    mpint  exponent
 *    mpint  modulus
 *
 * Next, there is a line saying "Private-Lines: " plus a number N,
 * and then N lines containing the (potentially encrypted) private
 * part of the key. For the key type "ssh-rsa", this will be
 * composed of
 *
 *    mpint  private_exponent
 *    mpint  p                  (the larger of the two primes)
 *    mpint  q                  (the smaller prime)
 *    mpint  iqmp               (the inverse of q modulo p)
 *    data   padding            (to reach a multiple of the cipher block size)
 *
 * And for "ssh-dss", it will be composed of
 *
 *    mpint  x                  (the private key parameter)
 *  [ string hash   20-byte hash of mpints p || q || g   only in old format ]
 *
 * Finally, there is a line saying "Private-MAC: " plus a hex
 * representation of a HMAC-SHA-1 of:
 *
 *    string  name of algorithm ("ssh-dss", "ssh-rsa")
 *    string  encryption type
 *    string  comment
 *    string  public-blob
 *    string  private-plaintext (the plaintext version of the
 *                               private part, including the final
 *                               padding)
 *
 * The key to the MAC is itself a SHA-1 hash of:
 *
 *    data    "putty-private-key-file-mac-key"
 *    data    passphrase
 *
 * (An empty passphrase is used for unencrypted keys.)
 *
 * If the key is encrypted, the encryption key is derived from the
 * passphrase by means of a succession of SHA-1 hashes. Each hash
 * is the hash of:
 *
 *    uint32  sequence-number
 *    data    passphrase
 *
 * where the sequence-number increases from zero. As many of these
 * hashes are used as necessary.
 *
 * For backwards compatibility with snapshots between 0.51 and
 * 0.52, we also support the older key file format, which begins
 * with "PuTTY-User-Key-File-1" (version number differs). In this
 * format the Private-MAC: field only covers the private-plaintext
 * field and nothing else (and without the 4-byte string length on
 * the front too). Moreover, the Private-MAC: field can be replaced
 * with a Private-Hash: field which is a plain SHA-1 hash instead of
 * an HMAC (this was generated for unencrypted keys).
 */
