-- The MIT License (MIT)
--
-- Copyright (c) 2016 Marvin Böcker
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for `revoked_certs`
-- ----------------------------
DROP TABLE IF EXISTS `revoked_certs`;
CREATE TABLE `revoked_certs` (
  `revoke_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `public_key` varchar(64) COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`revoke_id`),
  KEY `public_key` (`public_key`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- ----------------------------
-- Records of revoked_certs
-- ----------------------------
INSERT INTO `revoked_certs` VALUES ('1', '0000000000000000000000000000000000000000000000000000000000000000');
