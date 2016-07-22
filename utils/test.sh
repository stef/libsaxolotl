rm alice* bob*

./genidkey >alice.id || exit 1
#xxd -c 32 alice.id
./genidkey >bob.id || exit 1
#xxd -c 32 bob.id

./setup bob0 <bob.id || exit 1
#xxd -c 32 bob0.ctx
#xxd -c 32 bob0.pub
./setup alice0 <alice.id || exit 1
#xxd -c 32 alice0.ctx
#xxd -c 32 alice0.pub

./handshake alice0.ctx <bob0.pub || exit 1
#xxd -c 32 alice0.ctx
./handshake bob0.ctx <alice0.pub || exit 1
#xxd -c 32 bob0.ctx

echo -n "howdy" | ./box bob0.ctx | ./unbox alice0.ctx
