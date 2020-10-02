rm -rf /tmp/cstore
echo "Archive my_archive should be successfully created with password hahaha.\n"
./cstore init -p hahaha my_archive
./cstore init -p hahaha my_archive
./cstore list my_archive
./cstore list my_archiv
./cstore add -p hahaha my_archive ./testfiles/a.txt
./cstore list my_archive
./cstore add -p hahaha my_archive ./testfiles/a.txt ./testfiles/b.txt
./cstore add -p wrongpassword my_archive ./testfiles/c.txt

