


unsigned char xtime(unsigned char x){
    return (x << 1)^ ((x & 0x80) ? 0x1B : 0x00);
}


unsigned char multiply_bytes(unsigned char x, unsigned char y){
    unsigned char res = 0;
    while (y != 0) {
        if (y & 1)
            res ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return res;
}
