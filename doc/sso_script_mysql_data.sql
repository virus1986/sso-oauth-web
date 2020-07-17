/**
 * 用户表
 */
CREATE TABLE `sec_user` (
  `ID` varchar(38) COLLATE utf8_unicode_ci NOT NULL,
  `NAME` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
  `TYPE` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `LOGIN_ID` varchar(30) COLLATE utf8_unicode_ci DEFAULT NULL,
  `PASSWORD` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
  `EMAIL` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
  `MOBILE_PHONE` varchar(15) COLLATE utf8_unicode_ci DEFAULT NULL,
  `IM` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
  `TELEPHONE` varchar(15) COLLATE utf8_unicode_ci DEFAULT NULL,
  `SEX` varchar(1) COLLATE utf8_unicode_ci DEFAULT NULL,
  `BIRTHDAY` datetime DEFAULT NULL,
  `STATUS` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `ORG_ID` varchar(38) COLLATE utf8_unicode_ci DEFAULT NULL,
  `RANK` varchar(50) COLLATE utf8_unicode_ci DEFAULT NULL,
  `CREATED_BY` varchar(38) COLLATE utf8_unicode_ci DEFAULT NULL,
  `CREATED_DATE` datetime DEFAULT NULL,
  `LAST_UPDATED_BY` varchar(38) COLLATE utf8_unicode_ci DEFAULT NULL,
  `LAST_UPDATED_DATE` datetime DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `PK_SEC_USER` (`ID`) USING BTREE,
  UNIQUE KEY `AK_AK_USERLOGINID_SEC_USER` (`LOGIN_ID`,`TYPE`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


insert into `sec_user` (`ID`, `NAME`, `TYPE`, `LOGIN_ID`, `PASSWORD`, `EMAIL`, `MOBILE_PHONE`, `IM`, `TELEPHONE`, `SEX`, `BIRTHDAY`, `STATUS`, `ORG_ID`, `RANK`, `CREATED_BY`, `CREATED_DATE`, `LAST_UPDATED_BY`, `LAST_UPDATED_DATE`) values('43FE6476-CD7B-493B-8044-C7E3149D0876','系统管理员','local','admin','RrUz48yGLWgiUOOeOeUp6Q==',NULL,NULL,NULL,NULL,'U',NULL,'enabled','BFAB3E63-6A5D-46EE-B284-AE77CAE2074E',NULL,'43FE6476-CD7B-493B-8044-C7E3149D0876','2012-02-21 16:10:58','43FE6476-CD7B-493B-8044-C7E3149D0876','2012-05-21 03:28:34');



