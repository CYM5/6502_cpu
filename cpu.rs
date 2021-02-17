#![allow(non_snake_case)]

pub struct CPU{
    pub register_accu : u8,
    pub register_x: u8,
    pub status:u8, //processor flags
    pub pc : u16,
    pub register_y:u8,
    pub stack_ptr:u8,
    RAM: [u8; 0xFFFF],
}
const STACK: u16 = 0x0100;
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPage_X,
    ZeroPage_Y,
    Absolute,
    Absolute_X,
    Absolute_Y,
    Indirect_X,
    Indirect_Y,
}

impl CPU{
    pub fn new()-> Self{
        CPU{
            register_accu:0,
            register_x:0,
            register_y:0,
            status:0,
            pc:0,
            stack_ptr:0xfd,
            RAM:[0;0xFFFF],
        }
    }
    //IMPEL work with stack fr
    fn stack_pop(&mut self) -> u8 {
        self.stack_ptr = self.stack_ptr.wrapping_add(1);
        return self.read_RAM((STACK as u16)+self.stack_ptr as u16);
    }
    fn stack_pop_u16(&mut self) -> u16 {
        let low_data = self.stack_pop();
        let high_data = self.stack_pop();
        return u16::from_le_bytes([low_data, high_data]);

    }
    fn stack_push(&mut self, data: u8) {
        //println!("PUSHING -> {} TO {}", data, (STACK as u16) + self.stack_ptr as u16);
        self.write_RAM((STACK as u16) + self.stack_ptr as u16, data);
        self.stack_ptr = self.stack_ptr.wrapping_sub(1);
    }
    fn stack_push_u16(&mut self, data: u16) {
        let low_data = (data >> 8 ) as u8;
        let high_data = (data & 0xff) as u8;
        self.stack_push(high_data);
        self.stack_push(low_data);
    }
    //END
    //IMPLEM work with RAM fn
    fn write_RAM(&mut self, addr: u16, data:u8){
        //println!("{}", addr as usize);
        self.RAM[addr as usize] = data;
    }
    fn read_RAM(&mut self, addr:u16)-> u8{
        return self.RAM[addr as usize];
    }
    fn read_RAM_u16(&mut self, addr:u16) -> u16{
        let high_addr = self.read_RAM(addr) as u8;
        let low_addr = self.read_RAM(addr+1) as u8;
        u16::from_le_bytes([low_addr, high_addr]) //https://doc.rust-lang.org/std/primitive.u16.html#method.from_le_bytes
    }
    fn write_RAM_u16(&mut self, addr:u16, data:u16){
        let low_data = (data >> 8 ) as u8;
        let high_data = (data & 0xff) as u8;
        self.write_RAM(addr, low_data);
        self.write_RAM(addr+1, high_data);
        
    }
    //END

    pub fn reset_interrupt(&mut self){
        self.status=0;
        self.register_x=0;
        self.register_y=0;
        self.register_accu=0;
        self.stack_ptr = 0xfd;
        self.pc=self.read_RAM_u16(0xFFFC); //When a cartrigde is inserted the CPU put the PC at this addr
    }
    pub fn load_run(&mut self, program: Vec<u8>){
        self.RAM[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]); //Copy ROM PRG to NES RAM
        self.write_RAM_u16(0xFFFC, 0x8000);
        //self.reset_interrupt(); //DEBUG 
        self.pc=0x8000;
        self.run()
    }
    fn update_zero_neg_flag(&mut self, reg:u8){
        //updating negative flag Set if bit 7 of A is set
        if reg & 0b1000_0000 !=0{
            self.status = self.status |0b1000_0000;
        }
        else {
            self.status = self.status & 0b0111_1111;
        }
        //updating zero flags
        if reg == 0 {
            self.status = self.status | 0b0000_0010;
        }
        else {
            self.status=self.status & 0b1111_1101;
        }
    }
    pub fn get_operande_addr_with_addr_mode(&mut self, mode: &AddressingMode) -> u16{
        match mode {
            AddressingMode::Absolute => self.read_RAM_u16(self.pc) as u16,
            AddressingMode::ZeroPage => self.read_RAM(self.pc) as u16,
            AddressingMode::ZeroPage_X => {
                let point = self.read_RAM(self.pc);
                let addr = point.wrapping_add(self.register_x) as u16;
                return addr;
            },
            AddressingMode::ZeroPage_Y => {
                let point = self.read_RAM(self.pc);
                let addr = point.wrapping_add(self.register_y) as u16;
                return addr;
            },
            AddressingMode::Immediate => self.pc,
            AddressingMode::Indirect_X => {
                let base = self.read_RAM(self.pc);

                let ptr: u8 = (base as u8).wrapping_add(self.register_x);
                let lo = self.read_RAM(ptr as u16);
                let hi = self.read_RAM(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            },
            AddressingMode::Indirect_Y => {
                let base = self.read_RAM(self.pc);

                let ptr: u8 = (base as u8).wrapping_add(self.register_y);
                let lo = self.read_RAM(ptr as u16);
                let hi = self.read_RAM(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            },
            AddressingMode::Absolute_X => {
                let base = self.read_RAM_u16(self.pc);
                let addr = base.wrapping_add(self.register_x as u16);
                return addr;
            },
            AddressingMode::Absolute_Y => {
                let base = self.read_RAM_u16(self.pc);
                let addr = base.wrapping_add(self.register_y as u16);
                return addr;
            },


        }
    }
    pub fn lda(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let data = self.read_RAM(addr); 
        self.register_accu = data;
        self.update_zero_neg_flag(self.register_accu);
    }
    pub fn ldx(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let data = self.read_RAM(addr); 
        self.register_x = data;
        self.update_zero_neg_flag(self.register_x);
    }
    pub fn ldy(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let data = self.read_RAM(addr); 
        self.register_y = data;
        self.update_zero_neg_flag(self.register_y);
    }
    pub fn sta(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        self.write_RAM(addr, self.register_accu);
    }
    pub fn stx(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        self.write_RAM(addr, self.register_x);
    }
    pub fn sty(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        self.write_RAM(addr, self.register_y);
    }
    pub fn add_and_put_result_in_accu(&mut self, data:u8){
        let sum:u16;

        if(self.status & 0x0000_0001) != 0{ //C flag ? 
            sum = self.register_accu as u16 + data as u16 +1;
        }
        else {
            sum = self.register_accu as u16 + data as u16;
        }

        if sum>0xff{
            self.status = self.status |0b0000_0001; // put C flag to 1 
        }
        else {
            self.status = self.status &0b1111_1110; // put C flag to 0
        }
        let res = sum as u8;

        //Overflow flag
        //http://www.righto.com/2012/12/the-6502-overflow-flag-explained.html
        if (data ^ res) & (res ^ self.register_accu) & 0x80 != 0 {
            self.status = self.status |0b0100_0000; //put overflow flag to 1
        }
        else {
            self.status = self.status &0b1011_1111;//put overflow flag to 0
        }
        self.register_accu = res;
        self.update_zero_neg_flag(self.register_accu);

    }
    /*pub fn sub_and_put_result_in_accu(&mut self, data:u8){
        let sum:u16;
        //This instruction subtracts the contents of a memory location to the accumulator together with the not of the carry bit
        if(self.status & 0x0000_0001) != 0{ //C flag ? 
            sum = (self.register_accu as u16).wrapping_sub(data as u16);
        }
        else {
            sum = (self.register_accu as u16).wrapping_sub(data as u16).wrapping_sub(1); //A,Z,C,N = A-M-(1-C) 
        }

        if sum>0xff{
             // put C flag to 0 
             //f overflow occurs the carry bit is clear
            self.status = self.status &0b1111_1110;
        }
        else {
             // put C flag to 1
             self.status = self.status |0b0000_0001;
        }
        let res = sum as u8;

        //Overflow flag
        //http://www.righto.com/2012/12/the-6502-overflow-flag-explained.html
        if (data ^ res) & (res ^ self.register_accu) & 0x80 != 0 {
            self.status = self.status |0b0100_0000; //put overflow flag to 1
        }
        else {
            self.status = self.status &0b1011_1111;//put overflow flag to 0
        }
        self.register_accu = res;
        self.update_zero_neg_flag(self.register_accu);

    }*/ //BUGGY FN with the overflow flag, dunno why.
    pub fn adc(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        //println!("Will addr {}",addr);
        let data = self.read_RAM(addr);
        //println!("Will add {}",data);
        self.add_and_put_result_in_accu(data);
    }
    fn sbc(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        //println!("Will addr {}",addr);
        let data = self.read_RAM(addr);
        //println!("Will add {}",data);
        //self.sub_and_put_result_in_accu(data);
        self.add_and_put_result_in_accu(((data as i8).wrapping_neg().wrapping_sub(1)) as u8); //static void sbc(uint8_t arg) { adc(~arg); /* -arg - 1 */ }
    }
    fn and(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        //println!("Will addr {}",addr);
        let data = self.read_RAM(addr);
        let result = self.register_accu & data;
        self.register_accu = result;
        self.update_zero_neg_flag(self.register_accu);
    }
    fn lsr(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let mut data = self.read_RAM(addr);
        if data & 0b0000_0001 == 1 {
            self.status = self.status |0b0000_0001; // put C flag to 1
        } else {
            self.status = self.status &0b1111_1110; // put C flag to 0
        }
        data = data >> 1;
        self.write_RAM(addr, data);
        self.update_zero_neg_flag(data);
        //println!("{:?}", self.status);
    }
    fn asl(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let mut data = self.read_RAM(addr);
        if data >= 128 {
            self.status = self.status |0b0000_0001; // put C flag to 1
        } else {
            self.status = self.status &0b1111_1110; // put C flag to 0
        }
        data = data << 1;
        self.write_RAM(addr, data);
        self.update_zero_neg_flag(data);
        //println!("{:?}", self.status);
    }
    fn branch(&mut self){
        /*
Address  Hexdump   Dissassembly
-------------------------------
$0600    a2 08     LDX #$08
$0602    ca        DEX 
$0603    8e 00 02  STX $0200
$0606    e0 03     CPX #$03
$0608    d0 f8     BNE $0602

To understand branch the instruct is d0 f8, f8 is a signed 8 bits bin so it is equal to -8
So to do a correct jump you have to do pc + -8 + 1 the last +1 is to correct th execution flow 
        */
        let jmp:i8 = self.read_RAM(self.pc) as i8; //i8 because we sometime have to go back so the number can be neg
        let addr = self.pc.wrapping_add(1).wrapping_add(jmp as u16);
        self.pc = addr;
    }
    fn bit_test(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let data = self.read_RAM(addr);
        //println!("DATA {}", data);
        if data & 0b1000_0000 != 0 {
            self.status = self.status |0b1000_0000;
            //println!("CPU SET {}", self.status);
        }
        if data & 0b0100_0000 != 0 {
            self.status = self.status |0b0100_0000;
        }
        let result = self.register_accu & data;
        if result == 0 {
            self.status = self.status |0b0000_0010;
        }
        //println!("{}", self.register_accu);

    }
    fn cmp(&mut self, mode: &AddressingMode, register:u8){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let data = self.read_RAM(addr);
        if data <= register {
            self.status = self.status |0b0000_0001;
        }
        else {
            self.status = self.status &0b1111_1110;
        }
        let result = register.wrapping_sub(data);
        self.update_zero_neg_flag(result);
    }
    fn dec(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let mut data = self.read_RAM(addr);
        data = data.wrapping_sub(1);
        self.write_RAM(addr, data);
        self.update_zero_neg_flag(data);
    }
    fn eor(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let data = self.read_RAM(addr);
        let result = data ^self.register_accu;
        self.register_accu = result;
        self.update_zero_neg_flag(result);

    }
    fn ora(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let data = self.read_RAM(addr);
        let result = data |self.register_accu;
        self.register_accu = result;
        self.update_zero_neg_flag(result);

    }
    fn inc(&mut self, mode: &AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let mut data = self.read_RAM(addr);
        data = data.wrapping_add(1);
        self.write_RAM(addr, data);
        self.update_zero_neg_flag(data);
    }
    fn rol(&mut self, mode:&AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let mut data = self.read_RAM(addr);
        let carry_save = self.status & 0b0000_0001;
        //println!("CARRY {}", carry_save);
        if data >= 128 {
            self.status = self.status |0b0000_0001;
        }
        else {
            self.status = self.status &0b1111_1110;
        }
        data = data << 1;
        if carry_save == 1 {
            //println!("ADD 1");
            data = data |0b0000_0001;
        }
        self.write_RAM(addr, data);
        self.update_zero_neg_flag(data);
    }
    fn ror(&mut self, mode:&AddressingMode){
        let addr = self.get_operande_addr_with_addr_mode(mode);
        let mut data = self.read_RAM(addr);
        let carry_save = self.status & 0b0000_0001;
        //println!("CARRY {}", carry_save);
        if data & 1 == 1{
            self.status = self.status |0b0000_0001;
        }
        else {
            self.status = self.status &0b1111_1110;
        }
        data = data >> 1;
        if carry_save == 1 {
            //println!("ADD 1");
            data = data |0b1000_0000;
        }
        self.write_RAM(addr, data);
        self.update_zero_neg_flag(data);
    }

    pub fn run(&mut self){ //we need a mutable reference because we will update CPU
        loop{
            let opcode = self.read_RAM(self.pc);
            self.pc+=1;
            //println!("{:#02x}", self.pc);
            match opcode{
                //SBC
                0xE9 => {
                    self.sbc(&AddressingMode::Immediate);
                    self.pc+=1;
                }
                0xE5 => {
                    self.sbc(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0xF5 => {
                    self.sbc(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0xED => {
                    self.sbc(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0xFD => {
                    self.sbc(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                0xF9 => {
                    self.sbc(&AddressingMode::Absolute_Y);
                    self.pc+=2;
                }
                0xE1 => {
                    self.sbc(&AddressingMode::Indirect_X);
                    self.pc+=1;
                }
                0xF1 => {
                    self.sbc(&AddressingMode::Indirect_Y);
                    self.pc+=1;
                }
                //END SBC
                //RTS
                0x60 => {
                    self.pc = self.stack_pop_u16() +1 ; 
                }
                //END RTS
                //RTI
                0x40 => {
                    self.status = self.stack_pop();
                    self.pc= self.stack_pop_u16();
                }
                //END RTI
                //ROR
                0x6A => {
                    let mut data = self.register_accu;
                    let carry_save = self.status & 0b0000_0001;
                    if data & 1 == 1 {
                        self.status = self.status |0b0000_0001;
                    }
                    else {
                        self.status = self.status &0b1111_1110;
                    }
                    data = data >> 1;
                    if carry_save == 1 {
                        data = data |0b1000_0000;
                    }
                    self.register_accu=data;
                    self.update_zero_neg_flag(self.register_accu);
                }
                0x66 => {
                    self.ror(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x76 => {
                    self.ror(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x6E => {
                    self.ror(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x7E => {
                    self.ror(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                //END ROR
                //ROL
                0x2A => {
                    let mut data = self.register_accu;
                    let carry_save = self.status & 0b0000_0001;
                    if data >= 128 {
                        self.status = self.status |0b0000_0001;
                    }
                    else {
                        self.status = self.status &0b1111_1110;
                    }
                    data = data << 1;
                    if carry_save == 1 {
                        data = data |0b0000_0001;
                    }
                    self.register_accu=data;
                    self.update_zero_neg_flag(self.register_accu);
                }
                0x26 => {
                    self.rol(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x36 => {
                    self.rol(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x2E => {
                    self.rol(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x3E => {
                    self.rol(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                //END ROL
                //STACK opcode
                0x48 => {
                    self.stack_push(self.register_accu); //PHA
                }
                0x08 => {
                    self.stack_push(self.status); //PHP
                }
                0x68 => { //PLA
                    self.register_accu = self.stack_pop();
                    self.update_zero_neg_flag(self.register_accu);
                }
                0x28 => {
                    self.status = self.stack_pop();
                }
                //END stack opcode
                //ORA
                0x09 => {
                    self.ora(&AddressingMode::Immediate);
                    self.pc+=1;
                }
                0x05 => {
                    self.ora(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x15 => {
                    self.ora(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x0D => {
                    self.ora(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x1D => {
                    self.ora(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                0x19 => {
                    self.ora(&AddressingMode::Absolute_Y);
                    self.pc+=2;
                }
                0x01 => {
                    self.ora(&AddressingMode::Indirect_X);
                    self.pc+=1;
                }
                0x11 => {
                    self.ora(&AddressingMode::Indirect_Y);
                    self.pc+=1;
                }
                //END ORA
                0xEA => {} //NOP
                //JSR
                0x20 => {
                    self.stack_push_u16(self.pc + 2 - 1);
                    self.pc = self.read_RAM_u16(self.pc);
                }
                //END JSR
                //JMP
                0x4C => { //JMP ABSOLUTE
                    self.pc = self.read_RAM_u16(self.pc);
                } 
                0x6C => { //JMP INDIRECT 
                    /*
                    NB:
An original 6502 has does not correctly fetch the target address if the indirect vector falls on a page boundary (e.g. $xxFF where xx is any value from $00 to $FF). 
In this case fetches the LSB from $xxFF as expected but takes the MSB from $xx00. This is fixed in some later chips like the 65SC02 so for compatibility always ensure the indirect vector is not at the end of the page.

                    */
                    let addr = self.read_RAM_u16(self.pc);
                    if addr & 0x00FF == 0x00FF {
                        let lsb = self.read_RAM(addr);
                        let msb = self.read_RAM(addr & 0xFF00);
                        let return_addr = (msb as u16) << 8 | (lsb as u16);
                        self.pc = return_addr;
                    }
                    else {
                        let return_addr = self.read_RAM_u16(addr);
                        self.pc = return_addr;
                    }
                }
                //END JMP
                //INC
                0xE6 => {
                    self.inc(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0xF6 => {
                    self.inc(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0xEE => {
                    self.inc(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0xFE => {
                    self.inc(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                //END INC
                //EOR
                0x49 => {
                    self.eor(&AddressingMode::Immediate);
                    self.pc+=1;
                }
                0x45 => {
                    self.eor(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x55 => {
                    self.eor(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x4D => {
                    self.eor(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x5D => {
                    self.eor(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                0x59 => {
                    self.eor(&AddressingMode::Absolute_Y);
                    self.pc+=2;
                }
                0x41 => {
                    self.eor(&AddressingMode::Indirect_X);
                    self.pc+=1;
                }
                0x51 => {
                    self.eor(&AddressingMode::Indirect_Y);
                    self.pc+=1;
                }
                //END EOR 
                //DEy
                0x88 => {
                    self.register_y = self.register_y.wrapping_sub(1);
                    self.update_zero_neg_flag(self.register_y);
                }
                //END DEY
                //DEX
                0xCA => {
                    self.register_x = self.register_x.wrapping_sub(1);
                    self.update_zero_neg_flag(self.register_x);
                }
                //END DEX
                //DEC
                0xC6 => {
                    self.dec(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0xD6 => {
                    self.dec(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0xCE => {
                    self.dec(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0xDE => {
                    self.dec(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                //END DEC
                //CPY
                0xC0 => {
                    self.cmp(&AddressingMode::Immediate, self.register_y);
                    self.pc+=1;
                }
                0xC4 => {
                    self.cmp(&AddressingMode::ZeroPage, self.register_y);
                    self.pc+=1;
                }
                0xCC => {
                    self.cmp(&AddressingMode::Absolute, self.register_y);
                    self.pc+=2;
                }
                //END CPY
                //CPX
                0xE0 => {
                    self.cmp(&AddressingMode::Immediate, self.register_x);
                    self.pc+=1;
                }
                0xE4 => {
                    self.cmp(&AddressingMode::ZeroPage, self.register_x);
                    self.pc+=1;
                }
                0xEC => {
                    self.cmp(&AddressingMode::Absolute, self.register_x);
                    self.pc+=2;
                }
                //END CPX
                //CMP
                0xC9 => {
                    self.cmp(&AddressingMode::Immediate, self.register_accu);
                    self.pc+=1;
                }
                0xC5 => {
                    self.cmp(&AddressingMode::ZeroPage, self.register_accu);
                    self.pc+=1;
                }
                0xD5 => {
                    self.cmp(&AddressingMode::ZeroPage_X, self.register_accu);
                    self.pc+=1;
                }
                0xCD => {
                    self.cmp(&AddressingMode::Absolute, self.register_accu);
                    self.pc+=2;
                }
                0xDD => {
                    self.cmp(&AddressingMode::Absolute_X, self.register_accu);
                    self.pc+=2;
                }
                0xD9 => {
                    self.cmp(&AddressingMode::Absolute_Y, self.register_accu);
                    self.pc+=2;
                }
                0xC1 => {
                    self.cmp(&AddressingMode::Indirect_X, self.register_accu);
                    self.pc+=1;
                }
                0xD1 => {
                    self.cmp(&AddressingMode::Indirect_Y, self.register_accu);
                    self.pc+=1;
                }
                //END CMP
                //CPU status update opcade
                0x18 => {
                    //CLC - Clear Carry Flag
                    self.status=self.status & 0b1111_1110;
                }
                0x38 => {
                    //SEC - Set Carry Flag
                    self.status = self.status |0b0000_0001;
                }
                0xD8 => {
                    //CLD - Clear Decimal Mode
                    self.status=self.status & 0b1111_0111;
                }
                0xF8 => {
                    //SED - Set Decimal Flag
                    self.status = self.status |0b0000_1000;
                }
                0x58 => {
                    //CLI - Clear Interrupt Disable
                    self.status=self.status & 0b1111_1011;
                }
                0x78 => {
                    //SEI - Set Interrupt Disable
                    self.status = self.status |0b0000_0100;
                }
                0xB8 => {
                    //CLV - Clear Overflow Flag
                    self.status=self.status & 0b1011_1111;
                }
                //END CPU status update 
                //BRANCH

                0x90 => {
                    //BCC Branch if Carry Clear
                    if self.status & 0b0000_0001 == 0 {
                        self.branch();
                        //println!("JUMPED");
                    } else {
                        self.pc+=1; //we don't have jumped here so the flow continu
                    }
                }
                0xB0 => {
                    //BCS - Branch if Carry Set
                    if self.status & 0b0000_0001 != 0 {
                        self.branch();
                    } else {
                        self.pc+=1; //we don't have jumped here so the flow continu
                    }
                }
                0xF0 => {
                    //BEQ - Branch if Equal 
                    //If the zero flag is set
                    if self.status & 0b0000_0010 != 0 {
                        self.branch();
                    } else {
                        self.pc+=1; //we don't have jumped here so the flow continu
                    }
                }
                0xD0 => {
                    //BNE - Branch if Not Equal
                    //If the zero flag is clear 
                    if self.status & 0b0000_0010 == 0 {
                        self.branch();
                    } else {
                        self.pc+=1; //we don't have jumped here so the flow continu
                    }
                }
                0x30 => {
                    //BMI - Branch if Minus
                    //If the negative flag is set
                    if self.status & 0b1000_0000 != 0 {
                        self.branch();
                    } else {
                        self.pc+=1; //we don't have jumped here so the flow continu
                    }
                }
                0x10 => {
                    //BPL - Branch if Positive
                    //If the negative flag is clear
                    if self.status & 0b1000_0000 == 0 {
                        self.branch();
                    } else {
                        self.pc+=1; //we don't have jumped here so the flow continu
                    }
                }
                0x50 => {
                    //BVC - Branch if Overflow Clear
                    if self.status & 0b0100_0000 == 0 {
                        self.branch();
                    } else {
                        self.pc+=1; //we don't have jumped here so the flow continu
                    }
                }
                0x70 => {
                    //BVS - Branch if Overflow Set
                    if self.status & 0b0100_0000 != 0 {
                        self.branch();
                    } else {
                        self.pc+=1; //we don't have jumped here so the flow continu
                    }
                }
                //END BRANCH
                //BIT TEST 
                0x24 => {
                    self.bit_test(&AddressingMode::ZeroPage);
                    //println!("{}", self.register_accu);
                    self.pc+=1;
                }
                0x2C => {
                    self.bit_test(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                //END BIT TEST
                //LSR
                0x4A => {
                    let mut data = self.register_accu;
                    if data & 0b0000_0001 == 1 {
                        self.status = self.status |0b0000_0001; // put C flag to 1
                    }
                    else {
                        self.status = self.status &0b1111_1110; // put C flag to 0
                    }
                    data = data >>1;
                    self.register_accu=data;
                    self.update_zero_neg_flag(self.register_accu);
                }
                0x46 => {
                    self.lsr(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x56 => {
                    self.lsr(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x4E => {
                    self.lsr(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x5E => {
                    self.lsr(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                //END LSR
                //ASL IMPLEM
                0x0A => {
                    //ASL IN ACCU Register HERE
                    //ASL for RAM will be implem in a fn
                    let mut data = self.register_accu;
                    if data >= 128 {
                        self.status = self.status |0b0000_0001; // put C flag to 1
                    } else {
                        self.status = self.status &0b1111_1110; // put C flag to 0
                    }
                    data = data <<1;
                    self.register_accu = data;
                    self.update_zero_neg_flag(self.register_accu);
                    //Don't update the PC HERE because opcaode lenght == 1 
                }
                0x06 => {
                    self.asl(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x16 => {
                    self.asl(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x0E => {
                    self.asl(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x1E => {
                    self.asl(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                //END ASL
                //AND IMPLEM
                0x29 => {
                    self.and(&AddressingMode::Immediate);
                    self.pc+=1;
                }
                0x25 => {
                    self.and(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x35 => {
                    self.and(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x2D => {
                    self.and(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x3D => {
                    self.and(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                0x39 => {
                    self.and(&AddressingMode::Absolute_Y);
                    self.pc+=2;
                }
                0x21 => {
                    self.and(&AddressingMode::Indirect_X);
                    self.pc+=1;
                }
                0x31 => {
                    self.and(&AddressingMode::Indirect_Y);
                    self.pc+=1;
                }
                //END AND
                //ADC IMPLEM
                0x69 => {
                    self.adc(&AddressingMode::Immediate);
                    self.pc+=1;
                }
                0x65 => {
                    self.adc(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x75 => {
                    self.adc(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x6D => {
                    self.adc(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x7D => {
                    self.adc(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                0x79 => {
                    self.adc(&AddressingMode::Absolute_Y);
                    self.pc+=2;
                }
                0x61 => {
                    self.adc(&AddressingMode::Indirect_X);
                    self.pc+=1;
                }
                0x71 => {
                    self.adc(&AddressingMode::Indirect_Y);
                    self.pc+=1;
                }

                //ADC END
                
                //LDA IMPLEM
                0xA9 => { 
                    self.lda(&AddressingMode::Immediate);
                    self.pc+=1; //to move on the next instruct, this CPU can't have more than one param
                }
                0xA5 => {
                    self.lda(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0xB5 => {
                    self.lda(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0xAD => {
                    self.lda(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0xBD => {
                    self.lda(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                0xB9 => {
                    self.lda(&AddressingMode::Absolute_Y);
                    self.pc+=2;
                }
                0xA1 => {
                    self.lda(&AddressingMode::Indirect_X);
                    self.pc+=1;
                }
                0xB1 => {
                    self.lda(&AddressingMode::Indirect_Y);
                    self.pc+=1;
                }
                //END LDA
                //LDX IMPLEM
                0xA2 => { 
                    self.ldx(&AddressingMode::Immediate);
                    self.pc+=1; //to move on the next instruct, this CPU can't have more than one param
                }
                0xA6 => {
                    self.ldx(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0xAE => {
                    self.ldx(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0xB6 => {
                    self.ldx(&AddressingMode::ZeroPage_Y);
                    self.pc+=1;
                }
                0xBE => {
                    self.ldx(&AddressingMode::Absolute_Y);
                    self.pc+=2;
                }
                //END LDX
                //LDY IMPLEM
                0xA0 => { 
                    self.ldy(&AddressingMode::Immediate);
                    self.pc+=1; //to move on the next instruct, this CPU can't have more than one param
                }
                0xA4 => {
                    self.ldy(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0xAC => {
                    self.ldy(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0xB4 => {
                    self.ldy(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0xBC => {
                    self.ldy(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                //END LDY
                0xAA => { //TAX
                    self.register_x = self.register_accu;
                    self.update_zero_neg_flag(self.register_x);

                }
                0xA8 => { //TAY
                    self.register_y = self.register_accu;
                    self.update_zero_neg_flag(self.register_y);
                }
                0xBA => { //TSX
                    self.register_x = self.stack_ptr;
                    self.update_zero_neg_flag(self.register_x);
                }
                0x8A => { //TXA
                    self.register_accu = self.register_x;
                    self.update_zero_neg_flag(self.register_accu);
                }
                0x9A => { //TXS
                    self.stack_ptr = self.register_x;
                }
                0x98 => { //TYA
                    self.register_accu = self.register_y;
                    self.update_zero_neg_flag(self.register_accu);
                }
                //END TAX
                0xE8 => { //INX
                    self.register_x = self.register_x.wrapping_add(1); //https://doc.rust-lang.org/nightly/std/primitive.i8.html#method.wrapping_add
                    self.update_zero_neg_flag(self.register_x);
                }
                //END INX
                0xC8 => { //INY
                    self.register_y = self.register_y.wrapping_add(1); //https://doc.rust-lang.org/nightly/std/primitive.i8.html#method.wrapping_add
                    self.update_zero_neg_flag(self.register_y);
                }
                //END INY
                //STA IMPLEM
                0x85 => {
                    self.sta(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x95 => {
                    self.sta(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x8D => {
                    self.sta(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                0x9D => {
                    self.sta(&AddressingMode::Absolute_X);
                    self.pc+=2;
                }
                0x99 => {
                    self.sta(&AddressingMode::Absolute_Y);
                    self.pc+=2;
                }
                0x81=> {
                    self.sta(&AddressingMode::Indirect_X);
                    self.pc+=1;
                }
                0x91 => {
                    self.sta(&AddressingMode::Indirect_Y);
                    self.pc+=1;
                }
                //END STA
                //STX IMPLEM
                0x86 => {
                    self.stx(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x96 => {
                    self.stx(&AddressingMode::ZeroPage_Y);
                    self.pc+=1;
                }
                0x8E => {
                    self.stx(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                //END STX
                //STY IMPLEM
                0x84 => {
                    self.sty(&AddressingMode::ZeroPage);
                    self.pc+=1;
                }
                0x94 => {
                    self.sty(&AddressingMode::ZeroPage_X);
                    self.pc+=1;
                }
                0x8C => {
                    self.sty(&AddressingMode::Absolute);
                    self.pc+=2;
                }
                //END STY
                0x00 => {return;} //BRK
                _ => todo!()
            }
        }

    }
}

#[cfg(test)]
mod test {
   use super::*;
   #[test]
   fn test_0x38_set_carry_flag() {
       let mut cpu = CPU::new();
       cpu.load_run(vec![0x38]);
       assert_eq!(cpu.status, 1);
   }
   #[test]
   fn test_0x18_clear_carry_flag() {
    let mut cpu = CPU::new();
    cpu.status = 129;
    cpu.load_run(vec![0x18]);
    assert_eq!(cpu.status, 128);
}
#[test]
fn test_0x6A_ror_with_RAM() {
    let mut cpu = CPU::new();
    cpu.RAM[0x10] = 153;
    cpu.status=1;
    cpu.load_run(vec![0x66, 0x10]);
    assert_eq!(cpu.RAM[0x10], 204);
    //println!("{}", cpu.status);
    assert_eq!(cpu.status, 129);
}
#[test]
fn test_0x6A_ror_with_accu() {
    let mut cpu = CPU::new();
    cpu.register_accu = 153;
    cpu.status=0;
    cpu.load_run(vec![0x6A]);
    assert_eq!(cpu.register_accu, 76);
    //println!("{}", cpu.status);
    assert_eq!(cpu.status, 1);
}
#[test]
   fn test_stack_related_opcode() {
       let mut cpu = CPU::new();
       cpu.register_accu = 128;
       cpu.status = 50;
       cpu.load_run(vec![0x48, 0x08, 0x68, 0x28]);
       assert_eq!(cpu.register_accu, 50);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 128);
   }
   #[test]
   fn test_0x26_rol_with_carry() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10] = 153;
       cpu.status=1;
       cpu.load_run(vec![0x26, 0x10]);
       assert_eq!(cpu.RAM[0x10], 51);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 1);
   }
#[test]
   fn test_0x26_rol() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10] = 153;
       cpu.load_run(vec![0x26, 0x10]);
       assert_eq!(cpu.RAM[0x10], 50);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 1);
   }
#[test]
   fn test_0x05_ora() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10] = 90;
       cpu.register_accu = 50;
       cpu.load_run(vec![0x05, 0x10]);
       assert_eq!(cpu.register_accu, 122);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 0);
   }
#[test]
   fn test_stack_implem() {
       let mut cpu = CPU::new();
       cpu.register_accu = 5 ;
       cpu.RAM[0x10] = 255;
       cpu.stack_push(cpu.register_accu);
       //println!("{:?}", &cpu.RAM[250..270]);
       assert_eq!(cpu.RAM[0x01fd], 5);
       cpu.stack_push(cpu.RAM[0x10]);
       assert_eq!(cpu.RAM[0x01fc], 255);
       cpu.register_accu = cpu.stack_pop();
       assert_eq!(cpu.register_accu, 255);
       assert_eq!(cpu.stack_ptr, 0xfc);


   }
#[test]
   fn test_0xe6_inc_overflow() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10] = 255;
       cpu.load_run(vec![0xe6, 0x10]);
       assert_eq!(cpu.RAM[0x10], 0);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 2);
   }
#[test]
   fn test_0xe6_inc() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10] = 128;
       cpu.load_run(vec![0xe6, 0x10]);
       assert_eq!(cpu.RAM[0x10], 129);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 128);
   }
#[test]
   fn test_0x45_eor_zero() {
       let mut cpu = CPU::new();
       cpu.register_accu = 128;
       cpu.RAM[0x10] = 128;
       cpu.load_run(vec![0x45, 0x10]);
       assert_eq!(cpu.RAM[0x10], 128);
       //println!("{}", cpu.status);
       assert_eq!(cpu.register_accu, 0);
       assert_eq!(cpu.status, 2);
   }
#[test]
   fn test_0x45_eor() {
       let mut cpu = CPU::new();
       cpu.register_accu = 128;
       cpu.RAM[0x10] = 10;
       cpu.load_run(vec![0x45, 0x10]);
       assert_eq!(cpu.RAM[0x10], 10);
       //println!("{}", cpu.status);
       assert_eq!(cpu.register_accu, 138);
       assert_eq!(cpu.status, 128);
   }
#[test]
   fn test_0xc6_dec_zero_result() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10] = 1;
       cpu.load_run(vec![0xc6, 0x10]);
       assert_eq!(cpu.RAM[0x10], 0);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 2);
   }
#[test]
   fn test_0xc6_dec() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10] = 128;
       cpu.load_run(vec![0xc6, 0x10]);
       assert_eq!(cpu.RAM[0x10], 127);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 0);
   }
#[test]
   fn test_0xc5_cmp_unequal() {
       let mut cpu = CPU::new();
       cpu.register_accu = 129;
       cpu.RAM[0x10] = 128;
       cpu.load_run(vec![0xc5, 0x10]);
       assert_eq!(cpu.register_accu, 129);
       assert_eq!(cpu.RAM[0x10], 128);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 1);
   }
   #[test]
   fn test_0xe5_sbc() {
       let mut cpu = CPU::new();
       cpu.register_accu = 8;
       cpu.RAM[0x10] = 4;
       cpu.load_run(vec![0xe5, 0x10]);
       assert_eq!(cpu.register_accu, 3);
       assert_eq!(cpu.RAM[0x10], 4);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 1);
   }
   #[test]
   fn test_0xe5_sbc_complex() {
       let mut cpu = CPU::new();
       cpu.register_accu = 8;
       cpu.RAM[0x10] = 9;
       cpu.load_run(vec![0xe5, 0x10]);
       assert_eq!(cpu.register_accu, 0xFE);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 128);
   }
   #[test]
   fn test_0xc5_cmp_equal() {
       let mut cpu = CPU::new();
       cpu.register_accu = 129;
       cpu.RAM[0x10] = 129;
       cpu.load_run(vec![0xc5, 0x10]);
       assert_eq!(cpu.register_accu, 129);
       assert_eq!(cpu.RAM[0x10], 129);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 3);
   }
   #[test]
   fn test_0x24_bit_with_high_bit() {
       let mut cpu = CPU::new();
       cpu.register_accu = 129;
       cpu.RAM[0x10] = 150;
       cpu.load_run(vec![0x24, 0x10]);
       assert_eq!(cpu.register_accu, 129);
       assert_eq!(cpu.RAM[0x10], 150);
       //println!("{}", cpu.status);
       assert_eq!(cpu.status, 128);
   }
   #[test]
   fn test_0x24_bit() {
       let mut cpu = CPU::new();
       cpu.register_accu = 128;
       cpu.RAM[0x10] = 50;
       cpu.load_run(vec![0x24, 0x10]);
       assert_eq!(cpu.register_accu, 128);
       assert_eq!(cpu.RAM[0x10], 50);
       assert_eq!(cpu.status, 2);
   }
   #[test]
   fn test_0xB0_bcs_backward() {
       let mut cpu = CPU::new();
       cpu.status=0b0000_0001;
       cpu.load_run(vec![0xB0, 0xF8]);
       assert_eq!(cpu.pc, 0x7FFB);
   }
   #[test]
   fn test_0xB0_bcs() {
       let mut cpu = CPU::new();
       cpu.status=0b0000_0001;
       cpu.load_run(vec![0xB0, 0x05]);
       assert_eq!(cpu.pc, 0x8008);
   }
   #[test]
   fn test_0x90_bbc() {
       let mut cpu = CPU::new();
       cpu.status=0b0000_0000;
       cpu.load_run(vec![0x90, 0x02]);
       assert_eq!(cpu.pc, 0x8005);
   }
   #[test]
   fn test_0x0A_asl_accu() {
       let mut cpu = CPU::new();
       cpu.register_accu = 10;
       cpu.load_run(vec![0x0A]);
       assert_eq!(cpu.register_accu, 20);
       assert!(cpu.status & 0b0000_0010 == 0b00);
       assert!(cpu.status & 0b1000_0000 == 0);
       assert!(cpu.status & 0b0000_0001 == 0);
   }
   #[test]
   fn test_0x06_asl_in_RAM() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10]=90;
       cpu.load_run(vec![0x06, 0x10]);
       assert_eq!(cpu.RAM[0x10], 180);
       assert!(cpu.status & 0b0000_0010 == 0);
       assert!(cpu.status & 0b1000_0000 == 0b1000_0000);
       assert!(cpu.status & 0b0000_0001 == 0);
   }
   #[test]
   fn test_0x06_asl_in_RAM_and_Cflag() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10]=150;
       cpu.load_run(vec![0x06, 0x10]);
       assert_eq!(cpu.RAM[0x10], 44);
       assert!(cpu.status & 0b0000_0010 == 0);
       assert!(cpu.status & 0b1000_0000 < 128);
       assert!(cpu.status & 0b0000_0001 == 1);
   }
   #[test]
   fn test_0x4A_lsr_accu() {
       let mut cpu = CPU::new();
       cpu.register_accu = 10;
       cpu.load_run(vec![0x4A]);
       assert_eq!(cpu.register_accu, 5);
       assert!(cpu.status & 0b0000_0010 == 0b00);
       assert!(cpu.status & 0b1000_0000 == 0);
       assert!(cpu.status & 0b0000_0001 == 0);
   }
   
   #[test]
   fn test_0x46_lsr_in_RAM() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10]=90;
       cpu.load_run(vec![0x46, 0x10]);
       assert_eq!(cpu.RAM[0x10], 45);
       assert!(cpu.status & 0b0000_0010 == 0);
       assert!(cpu.status & 0b1000_0000 == 0b0000_0000);
       assert!(cpu.status & 0b0000_0001 == 0);
   }
   #[test]
   fn test_0x46_lsr_in_RAM_and_Cflag() {
       let mut cpu = CPU::new();
       cpu.RAM[0x10]=151;
       cpu.load_run(vec![0x46, 0x10]);
       assert_eq!(cpu.RAM[0x10], 75);
       assert!(cpu.status & 0b0000_0010 == 0);
       assert!(cpu.status & 0b1000_0000 < 128);
       assert!(cpu.status & 0b0000_0001 == 1);
   }
   #[test]
   fn test_0x65_adc_add() {
       let mut cpu = CPU::new();
       cpu.register_accu = 10;
       cpu.RAM[0x10]=90;
       cpu.load_run(vec![0x65, 0x10]);
       assert_eq!(cpu.register_accu, 100);
       assert!(cpu.status & 0b0000_0010 == 0b00);
       assert!(cpu.status & 0b1000_0000 == 0);
       assert!(cpu.status & 0b0000_0001 == 0);
   }
   #[test]
   fn test_0x25_and_accu() {
       let mut cpu = CPU::new();
       cpu.register_accu = 10;
       cpu.RAM[0x10]=90;
       cpu.load_run(vec![0x25, 0x10]);
       assert_eq!(cpu.register_accu, 10);
       assert!(cpu.status & 0b0000_0010 == 0b00);
       assert!(cpu.status & 0b1000_0000 == 0);
       
       
   }
   #[test]
   fn test_0x65_adc_add_with_c_flag() {
       let mut cpu = CPU::new();
       cpu.register_accu = 10;
       cpu.RAM[0x10]=253;
       cpu.load_run(vec![0x65, 0x10]);
       assert_eq!(cpu.register_accu, 7);
       assert!(cpu.status & 0b0000_0010 == 0b00);
       assert!(cpu.status & 0b1000_0000 == 0);
       assert!(cpu.status & 0b0000_0001 != 0);
   }
   #[test]
   fn test_0xa9_lda_immidiate_load_data() {
       let mut cpu = CPU::new();
       cpu.load_run(vec![0xa9, 0x05, 0x00]);
       assert_eq!(cpu.register_accu, 0x05);
       assert!(cpu.status & 0b0000_0010 == 0b00);
       assert!(cpu.status & 0b1000_0000 == 0);
   }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_run(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status & 0b0000_0010 == 0b10);
    }
    #[test]
    fn test_0xa2_ldx_immidiate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_run(vec![0xa2, 0x05, 0x00]);
        assert_eq!(cpu.register_x, 0x05);
        assert!(cpu.status & 0b0000_0010 == 0b00);
        assert!(cpu.status & 0b1000_0000 == 0);
    }
 
     #[test]
     fn test_0xa2_ldx_zero_flag() {
         let mut cpu = CPU::new();
         cpu.load_run(vec![0xa2, 0x00, 0x00]);
         assert!(cpu.status & 0b0000_0010 == 0b10);
     }
     #[test]
     fn test_0xa0_ldy_immidiate_load_data() {
         let mut cpu = CPU::new();
         cpu.load_run(vec![0xa0, 0x05, 0x00]);
         assert_eq!(cpu.register_y, 0x05);
         assert!(cpu.status & 0b0000_0010 == 0b00);
         assert!(cpu.status & 0b1000_0000 == 0);
     }
  
      #[test]
      fn test_0xa0_ldy_zero_flag() {
          let mut cpu = CPU::new();
          cpu.load_run(vec![0xa0, 0x00, 0x00]);
          assert!(cpu.status & 0b0000_0010 == 0b10);
      }
    #[test]
    fn test_0xaa_tax_move_a_to_x() {
        let mut cpu = CPU::new();
        cpu.register_accu = 10;
        cpu.load_run(vec![0xaa, 0x00]);
  
        assert_eq!(cpu.register_x, 10)
    }
    #[test]
    fn test_5_ops_working_together() {
        let mut cpu = CPU::new();
        cpu.load_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);
  
        assert_eq!(cpu.register_x, 0xc1)
    }
 
     #[test]
     fn test_inx_overflow() {
         let mut cpu = CPU::new();
         cpu.register_x = 0xff;
         cpu.load_run(vec![0xe8, 0xe8, 0x00]);
 
         assert_eq!(cpu.register_x, 1)
     }
     #[test]
     fn test_lda_from_memory() {
         let mut cpu = CPU::new();
         cpu.write_RAM(0x10, 0x55);
         println!("{:?}", &cpu.RAM[0..17]);
         cpu.load_run(vec![0xa5, 0x10, 0x00]);
  
         assert_eq!(cpu.register_accu, 0x55);
     }
     #[test]
     fn test_sta_implem() {
         let mut cpu = CPU::new();
         cpu.register_accu = 10;
         cpu.load_run(vec![0x85, 0x10]);
   
         assert_eq!(cpu.RAM[0x10], 10)
     }
     #[test]
     fn test_stx_implem() {
         let mut cpu = CPU::new();
         cpu.register_x = 20;
         cpu.load_run(vec![0x86, 0x10]);
   
         assert_eq!(cpu.RAM[0x10], 20)
     }
     #[test]
     fn test_sty_implem() {
         let mut cpu = CPU::new();
         cpu.register_y = 20;
         cpu.load_run(vec![0x94, 0x10]);
         println!("{:?}",&cpu.RAM[0..17]);
         let test = cpu.get_operande_addr_with_addr_mode(&AddressingMode::Absolute);
         println!("{}",test);
   
         assert_eq!(cpu.RAM[0x10], 20)
     }
}