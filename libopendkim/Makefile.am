lib_LIBRARIES = libopendkim.a
libopendkim_a_SOURCES = base64.c dkim-cache.c dkim-canon.c dkim-keys.c dkim-policy.c dkim-rep.c dkim-tables.c dkim-test.c dkim-ub.c dkim-util.c dkim.c rfc2822.c util.c vbr.c
libopendkim_a_CFLAGS = 

if BODYLENGTH_DB
libopendkim_a_CFLAGS += -D_FFR_BODYLENGTH_DB
endif

if DIFFHEADERS
libopendkim_a_CFLAGS += -D_FFR_DIFFHEADERS
endif

if DKIM_REPUTATION
libopendkim_a_CFLAGS += -D_FFR_DKIM_REPUTATION
endif

if DNS_UPGRADE
libopendkim_a_CFLAGS += -D_FFR_DNS_UPGRADE
endif

if PARSE_TIME
libopendkim_a_CFLAGS += -D_FFR_PARSE_TIME
endif

if STATS
libopendkim_a_CFLAGS += -D_FFR_STATS
endif

if USE_ARLIB
libopendkim_a_CFLAGS += -DUSE_ARLIB
endif

if VBR
libopendkim_a_CFLAGS += -D_FFR_VBR
endif

check_PROGRAMS = t-setup t-test00 t-test01 t-test02 t-test03 t-test04 \
	t-test05 t-test06 t-test07 t-test08 t-test09 t-test10 t-test11 \
	t-test12 t-test13 t-test14 t-test15 t-test16 t-test17 t-test18 \
	t-test19 t-test20 t-test21 t-test22 t-test23 t-test24 t-test25 \
	t-test26 t-test27 t-test28 t-test29 t-test30 t-test31 t-test32 \
	t-test33 t-test34 t-test35 t-test36 t-test37 t-test38 t-test39 \
	t-test40 t-test41 t-test42 t-test43 t-test44 t-test45 t-test46 \
	t-test47 t-test48 t-test49 t-test50 t-test51 t-test52 t-test53 \
	t-test54 t-test55 t-test56 t-test57 t-test58 t-test59 t-test60 \
	t-test61 t-test62 t-test63 t-test64 t-test65 t-test66 t-test67 \
	t-test68 t-test69 t-test70 t-test71 t-test72 t-test73 t-test74 \
	t-test75 t-test76 t-test77 t-test78 t-test79 t-test80 t-test81 \
	t-test82 t-test83 t-test84 t-test85 t-test86 t-test87 t-test88 \
	t-test89 t-test90 t-test91 t-test92 t-test93 t-test94 t-test95 \
	t-test96 t-test97 t-test98 t-test99 t-test100 t-test101 t-test102 \
	t-test103 t-test104 t-test105 t-test106 t-test107 t-test108 \
	t-test109 t-test110 t-test111 t-test112 t-test113 t-test114 \
	t-test115 t-test116 t-test117 t-test118 t-test119 t-test120 \
	t-test121 t-test122 t-test123 t-test124 t-test125 t-test126 \
	t-test127 t-signperf t-verifyperf t-cleanup
TESTS = $(check_PROGRAMS)

t_setup_SOURCES = t-setup.c
t_setup_LDFLAGS = -L.
t_setup_LDADD = ./libopendkim.a

t_cleanup_SOURCES = t-cleanup.c
t_cleanup_LDFLAGS = -L.
t_cleanup_LDADD = ./libopendkim.a

t_signperf_SOURCES = t-signperf.c
t_signperf_LDFLAGS = -L.
t_signperf_LDADD = ./libopendkim.a

t_verifyperf_SOURCES = t-verifyperf.c
t_verifyperf_LDFLAGS = -L.
t_verifyperf_LDADD = ./libopendkim.a

t_test00_SOURCES = t-test00.c
t_test00_LDFLAGS = -L.
t_test00_LDADD = ./libopendkim.a

t_test01_SOURCES = t-test01.c
t_test01_LDFLAGS = -L.
t_test01_LDADD = ./libopendkim.a

t_test02_SOURCES = t-test02.c
t_test02_LDFLAGS = -L.
t_test02_LDADD = ./libopendkim.a

t_test03_SOURCES = t-test03.c
t_test03_LDFLAGS = -L.
t_test03_LDADD = ./libopendkim.a

t_test04_SOURCES = t-test04.c
t_test04_LDFLAGS = -L.
t_test04_LDADD = ./libopendkim.a

t_test05_SOURCES = t-test05.c
t_test05_LDFLAGS = -L.
t_test05_LDADD = ./libopendkim.a

t_test06_SOURCES = t-test06.c
t_test06_LDFLAGS = -L.
t_test06_LDADD = ./libopendkim.a

t_test07_SOURCES = t-test07.c
t_test07_LDFLAGS = -L.
t_test07_LDADD = ./libopendkim.a

t_test08_SOURCES = t-test08.c
t_test08_LDFLAGS = -L.
t_test08_LDADD = ./libopendkim.a

t_test09_SOURCES = t-test09.c
t_test09_LDFLAGS = -L.
t_test09_LDADD = ./libopendkim.a

t_test10_SOURCES = t-test10.c
t_test10_LDFLAGS = -L.
t_test10_LDADD = ./libopendkim.a

t_test11_SOURCES = t-test11.c
t_test11_LDFLAGS = -L.
t_test11_LDADD = ./libopendkim.a

t_test12_SOURCES = t-test12.c
t_test12_LDFLAGS = -L.
t_test12_LDADD = ./libopendkim.a

t_test13_SOURCES = t-test13.c
t_test13_LDFLAGS = -L.
t_test13_LDADD = ./libopendkim.a

t_test14_SOURCES = t-test14.c
t_test14_LDFLAGS = -L.
t_test14_LDADD = ./libopendkim.a

t_test15_SOURCES = t-test15.c
t_test15_LDFLAGS = -L.
t_test15_LDADD = ./libopendkim.a

t_test16_SOURCES = t-test16.c
t_test16_LDFLAGS = -L.
t_test16_LDADD = ./libopendkim.a

t_test17_SOURCES = t-test17.c
t_test17_LDFLAGS = -L.
t_test17_LDADD = ./libopendkim.a

t_test18_SOURCES = t-test18.c
t_test18_LDFLAGS = -L.
t_test18_LDADD = ./libopendkim.a

t_test19_SOURCES = t-test19.c
t_test19_LDFLAGS = -L.
t_test19_LDADD = ./libopendkim.a

t_test20_SOURCES = t-test20.c
t_test20_LDFLAGS = -L.
t_test20_LDADD = ./libopendkim.a

t_test21_SOURCES = t-test21.c
t_test21_LDFLAGS = -L.
t_test21_LDADD = ./libopendkim.a

t_test22_SOURCES = t-test22.c
t_test22_LDFLAGS = -L.
t_test22_LDADD = ./libopendkim.a

t_test23_SOURCES = t-test23.c
t_test23_LDFLAGS = -L.
t_test23_LDADD = ./libopendkim.a

t_test24_SOURCES = t-test24.c
t_test24_LDFLAGS = -L.
t_test24_LDADD = ./libopendkim.a

t_test25_SOURCES = t-test25.c
t_test25_LDFLAGS = -L.
t_test25_LDADD = ./libopendkim.a

t_test26_SOURCES = t-test26.c
t_test26_LDFLAGS = -L.
t_test26_LDADD = ./libopendkim.a

t_test27_SOURCES = t-test27.c
t_test27_LDFLAGS = -L.
t_test27_LDADD = ./libopendkim.a

t_test28_SOURCES = t-test28.c
t_test28_LDFLAGS = -L.
t_test28_LDADD = ./libopendkim.a

t_test29_SOURCES = t-test29.c
t_test29_LDFLAGS = -L.
t_test29_LDADD = ./libopendkim.a

t_test30_SOURCES = t-test30.c
t_test30_LDFLAGS = -L.
t_test30_LDADD = ./libopendkim.a

t_test31_SOURCES = t-test31.c
t_test31_LDFLAGS = -L.
t_test31_LDADD = ./libopendkim.a

t_test32_SOURCES = t-test32.c
t_test32_LDFLAGS = -L.
t_test32_LDADD = ./libopendkim.a

t_test33_SOURCES = t-test33.c
t_test33_LDFLAGS = -L.
t_test33_LDADD = ./libopendkim.a

t_test34_SOURCES = t-test34.c
t_test34_LDFLAGS = -L.
t_test34_LDADD = ./libopendkim.a

t_test35_SOURCES = t-test35.c
t_test35_LDFLAGS = -L.
t_test35_LDADD = ./libopendkim.a

t_test36_SOURCES = t-test36.c
t_test36_LDFLAGS = -L.
t_test36_LDADD = ./libopendkim.a

t_test37_SOURCES = t-test37.c
t_test37_LDFLAGS = -L.
t_test37_LDADD = ./libopendkim.a

t_test38_SOURCES = t-test38.c
t_test38_LDFLAGS = -L.
t_test38_LDADD = ./libopendkim.a

t_test39_SOURCES = t-test39.c
t_test39_LDFLAGS = -L.
t_test39_LDADD = ./libopendkim.a

t_test40_SOURCES = t-test40.c
t_test40_LDFLAGS = -L.
t_test40_LDADD = ./libopendkim.a

t_test41_SOURCES = t-test41.c
t_test41_LDFLAGS = -L.
t_test41_LDADD = ./libopendkim.a

t_test42_SOURCES = t-test42.c
t_test42_LDFLAGS = -L.
t_test42_LDADD = ./libopendkim.a

t_test43_SOURCES = t-test43.c
t_test43_LDFLAGS = -L.
t_test43_LDADD = ./libopendkim.a

t_test44_SOURCES = t-test44.c
t_test44_LDFLAGS = -L.
t_test44_LDADD = ./libopendkim.a

t_test45_SOURCES = t-test45.c
t_test45_LDFLAGS = -L.
t_test45_LDADD = ./libopendkim.a

t_test46_SOURCES = t-test46.c
t_test46_LDFLAGS = -L.
t_test46_LDADD = ./libopendkim.a

t_test47_SOURCES = t-test47.c
t_test47_LDFLAGS = -L.
t_test47_LDADD = ./libopendkim.a

t_test48_SOURCES = t-test48.c
t_test48_LDFLAGS = -L.
t_test48_LDADD = ./libopendkim.a

t_test49_SOURCES = t-test49.c
t_test49_LDFLAGS = -L.
t_test49_LDADD = ./libopendkim.a

t_test50_SOURCES = t-test50.c
t_test50_LDFLAGS = -L.
t_test50_LDADD = ./libopendkim.a

t_test51_SOURCES = t-test51.c
t_test51_LDFLAGS = -L.
t_test51_LDADD = ./libopendkim.a

t_test52_SOURCES = t-test52.c
t_test52_LDFLAGS = -L.
t_test52_LDADD = ./libopendkim.a

t_test53_SOURCES = t-test53.c
t_test53_LDFLAGS = -L.
t_test53_LDADD = ./libopendkim.a

t_test54_SOURCES = t-test54.c
t_test54_LDFLAGS = -L.
t_test54_LDADD = ./libopendkim.a

t_test55_SOURCES = t-test55.c
t_test55_LDFLAGS = -L.
t_test55_LDADD = ./libopendkim.a

t_test56_SOURCES = t-test56.c
t_test56_LDFLAGS = -L.
t_test56_LDADD = ./libopendkim.a

t_test57_SOURCES = t-test57.c
t_test57_LDFLAGS = -L.
t_test57_LDADD = ./libopendkim.a

t_test58_SOURCES = t-test58.c
t_test58_LDFLAGS = -L.
t_test58_LDADD = ./libopendkim.a

t_test59_SOURCES = t-test59.c
t_test59_LDFLAGS = -L.
t_test59_LDADD = ./libopendkim.a

t_test60_SOURCES = t-test60.c
t_test60_LDFLAGS = -L.
t_test60_LDADD = ./libopendkim.a

t_test61_SOURCES = t-test61.c
t_test61_LDFLAGS = -L.
t_test61_LDADD = ./libopendkim.a

t_test62_SOURCES = t-test62.c
t_test62_LDFLAGS = -L.
t_test62_LDADD = ./libopendkim.a

t_test63_SOURCES = t-test63.c
t_test63_LDFLAGS = -L.
t_test63_LDADD = ./libopendkim.a

t_test64_SOURCES = t-test64.c
t_test64_LDFLAGS = -L.
t_test64_LDADD = ./libopendkim.a

t_test65_SOURCES = t-test65.c
t_test65_LDFLAGS = -L.
t_test65_LDADD = ./libopendkim.a

t_test66_SOURCES = t-test66.c
t_test66_LDFLAGS = -L.
t_test66_LDADD = ./libopendkim.a

t_test67_SOURCES = t-test67.c
t_test67_LDFLAGS = -L.
t_test67_LDADD = ./libopendkim.a

t_test68_SOURCES = t-test68.c
t_test68_LDFLAGS = -L.
t_test68_LDADD = ./libopendkim.a

t_test69_SOURCES = t-test69.c
t_test69_LDFLAGS = -L.
t_test69_LDADD = ./libopendkim.a

t_test70_SOURCES = t-test70.c
t_test70_LDFLAGS = -L.
t_test70_LDADD = ./libopendkim.a

t_test71_SOURCES = t-test71.c
t_test71_LDFLAGS = -L.
t_test71_LDADD = ./libopendkim.a

t_test72_SOURCES = t-test72.c
t_test72_LDFLAGS = -L.
t_test72_LDADD = ./libopendkim.a

t_test73_SOURCES = t-test73.c
t_test73_LDFLAGS = -L.
t_test73_LDADD = ./libopendkim.a

t_test74_SOURCES = t-test74.c
t_test74_LDFLAGS = -L.
t_test74_LDADD = ./libopendkim.a

t_test75_SOURCES = t-test75.c
t_test75_LDFLAGS = -L.
t_test75_LDADD = ./libopendkim.a

t_test76_SOURCES = t-test76.c
t_test76_LDFLAGS = -L.
t_test76_LDADD = ./libopendkim.a

t_test77_SOURCES = t-test77.c
t_test77_LDFLAGS = -L.
t_test77_LDADD = ./libopendkim.a

t_test78_SOURCES = t-test78.c
t_test78_LDFLAGS = -L.
t_test78_LDADD = ./libopendkim.a

t_test79_SOURCES = t-test79.c
t_test79_LDFLAGS = -L.
t_test79_LDADD = ./libopendkim.a

t_test80_SOURCES = t-test80.c
t_test80_LDFLAGS = -L.
t_test80_LDADD = ./libopendkim.a

t_test81_SOURCES = t-test81.c
t_test81_LDFLAGS = -L.
t_test81_LDADD = ./libopendkim.a

t_test82_SOURCES = t-test82.c
t_test82_LDFLAGS = -L.
t_test82_LDADD = ./libopendkim.a

t_test83_SOURCES = t-test83.c
t_test83_LDFLAGS = -L.
t_test83_LDADD = ./libopendkim.a

t_test84_SOURCES = t-test84.c
t_test84_LDFLAGS = -L.
t_test84_LDADD = ./libopendkim.a

t_test85_SOURCES = t-test85.c
t_test85_LDFLAGS = -L.
t_test85_LDADD = ./libopendkim.a

t_test86_SOURCES = t-test86.c
t_test86_LDFLAGS = -L.
t_test86_LDADD = ./libopendkim.a

t_test87_SOURCES = t-test87.c
t_test87_LDFLAGS = -L.
t_test87_LDADD = ./libopendkim.a

t_test88_SOURCES = t-test88.c
t_test88_LDFLAGS = -L.
t_test88_LDADD = ./libopendkim.a

t_test89_SOURCES = t-test89.c
t_test89_LDFLAGS = -L.
t_test89_LDADD = ./libopendkim.a

t_test90_SOURCES = t-test90.c
t_test90_LDFLAGS = -L.
t_test90_LDADD = ./libopendkim.a

t_test91_SOURCES = t-test91.c
t_test91_LDFLAGS = -L.
t_test91_LDADD = ./libopendkim.a

t_test92_SOURCES = t-test92.c
t_test92_LDFLAGS = -L.
t_test92_LDADD = ./libopendkim.a

t_test93_SOURCES = t-test93.c
t_test93_LDFLAGS = -L.
t_test93_LDADD = ./libopendkim.a

t_test94_SOURCES = t-test94.c
t_test94_LDFLAGS = -L.
t_test94_LDADD = ./libopendkim.a

t_test95_SOURCES = t-test95.c
t_test95_LDFLAGS = -L.
t_test95_LDADD = ./libopendkim.a

t_test96_SOURCES = t-test96.c
t_test96_LDFLAGS = -L.
t_test96_LDADD = ./libopendkim.a

t_test97_SOURCES = t-test97.c
t_test97_LDFLAGS = -L.
t_test97_LDADD = ./libopendkim.a

t_test98_SOURCES = t-test98.c
t_test98_LDFLAGS = -L.
t_test98_LDADD = ./libopendkim.a

t_test99_SOURCES = t-test99.c
t_test99_LDFLAGS = -L.
t_test99_LDADD = ./libopendkim.a

t_test100_SOURCES = t-test100.c
t_test100_LDFLAGS = -L.
t_test100_LDADD = ./libopendkim.a

t_test101_SOURCES = t-test101.c
t_test101_LDFLAGS = -L.
t_test101_LDADD = ./libopendkim.a

t_test102_SOURCES = t-test102.c
t_test102_LDFLAGS = -L.
t_test102_LDADD = ./libopendkim.a

t_test103_SOURCES = t-test103.c
t_test103_LDFLAGS = -L.
t_test103_LDADD = ./libopendkim.a

t_test104_SOURCES = t-test104.c
t_test104_LDFLAGS = -L.
t_test104_LDADD = ./libopendkim.a

t_test105_SOURCES = t-test105.c
t_test105_LDFLAGS = -L.
t_test105_LDADD = ./libopendkim.a

t_test106_SOURCES = t-test106.c
t_test106_LDFLAGS = -L.
t_test106_LDADD = ./libopendkim.a

t_test107_SOURCES = t-test107.c
t_test107_LDFLAGS = -L.
t_test107_LDADD = ./libopendkim.a

t_test108_SOURCES = t-test108.c
t_test108_LDFLAGS = -L.
t_test108_LDADD = ./libopendkim.a

t_test109_SOURCES = t-test109.c
t_test109_LDFLAGS = -L.
t_test109_LDADD = ./libopendkim.a

t_test110_SOURCES = t-test110.c
t_test110_LDFLAGS = -L.
t_test110_LDADD = ./libopendkim.a

t_test111_SOURCES = t-test111.c
t_test111_LDFLAGS = -L.
t_test111_LDADD = ./libopendkim.a

t_test112_SOURCES = t-test112.c
t_test112_LDFLAGS = -L.
t_test112_LDADD = ./libopendkim.a

t_test113_SOURCES = t-test113.c
t_test113_LDFLAGS = -L.
t_test113_LDADD = ./libopendkim.a

t_test114_SOURCES = t-test114.c
t_test114_LDFLAGS = -L.
t_test114_LDADD = ./libopendkim.a

t_test115_SOURCES = t-test115.c
t_test115_LDFLAGS = -L.
t_test115_LDADD = ./libopendkim.a

t_test116_SOURCES = t-test116.c
t_test116_LDFLAGS = -L.
t_test116_LDADD = ./libopendkim.a

t_test117_SOURCES = t-test117.c
t_test117_LDFLAGS = -L.
t_test117_LDADD = ./libopendkim.a

t_test118_SOURCES = t-test118.c
t_test118_LDFLAGS = -L.
t_test118_LDADD = ./libopendkim.a

t_test119_SOURCES = t-test119.c
t_test119_LDFLAGS = -L.
t_test119_LDADD = ./libopendkim.a

t_test120_SOURCES = t-test120.c
t_test120_LDFLAGS = -L.
t_test120_LDADD = ./libopendkim.a

t_test121_SOURCES = t-test121.c
t_test121_LDFLAGS = -L.
t_test121_LDADD = ./libopendkim.a

t_test122_SOURCES = t-test122.c
t_test122_LDFLAGS = -L.
t_test122_LDADD = ./libopendkim.a

t_test123_SOURCES = t-test123.c
t_test123_LDFLAGS = -L.
t_test123_LDADD = ./libopendkim.a

t_test124_SOURCES = t-test124.c
t_test124_LDFLAGS = -L.
t_test124_LDADD = ./libopendkim.a

t_test125_SOURCES = t-test125.c
t_test125_LDFLAGS = -L.
t_test125_LDADD = ./libopendkim.a

t_test126_SOURCES = t-test126.c
t_test126_LDFLAGS = -L.
t_test126_LDADD = ./libopendkim.a

t_test127_SOURCES = t-test127.c
t_test127_LDFLAGS = -L.
t_test127_LDADD = ./libopendkim.a
