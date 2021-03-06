load data 
append 
into table sn_day_regi_13 
fields terminated by '`' 
(P_SEPA    CHAR,
FILE_NM   CHAR,
SEQNO     INTEGER EXTERNAL,
CR_TIME   TIMESTAMP "YYYY-MM-DD HH24:MI:SS.FF9",
SRC_IP    CHAR,
DEST_IP   CHAR,
MTHD_NM   CHAR,
TO_NO     CHAR,
TO_DOM    CHAR,
FROM_NO   CHAR,
FROM_DOM  CHAR,
CALLID    CHAR,
SRC_PORT  CHAR,
DEST_PORT CHAR,
C_SEQ     CHAR,
C_MTHD    CHAR,
UA        CHAR,
EXPIRE    INTEGER EXTERNAL,
BASE_PTR  INTEGER EXTERNAL,
OFFSET    INTEGER EXTERNAL)
