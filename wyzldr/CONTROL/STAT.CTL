load data 
append 
into table xk_host_stat
fields terminated by '`' 
(
  ST_DT      CHAR,
  SRC_IP     CHAR,
  DST_IP     CHAR,
  REG_REQ    INTEGER EXTERNAL,
  REG_200    INTEGER EXTERNAL,
  REG_401    INTEGER EXTERNAL,
  REG_404    INTEGER EXTERNAL,
  INV_REQ    INTEGER EXTERNAL,
  INV_200    INTEGER EXTERNAL,
  INV_487    INTEGER EXTERNAL,
  INV_500    INTEGER EXTERNAL,
  INV_503    INTEGER EXTERNAL
)
