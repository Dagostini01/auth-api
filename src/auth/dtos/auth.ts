import { IsEmail, IsNotEmpty } from "class-validator";

export class signUpDTO {
    @IsNotEmpty()
    name: string;
    @IsEmail()
    email: string;
    @IsNotEmpty()
    password: string;
}

export class signInDTO {
    @IsEmail()
    email: string;
    @IsNotEmpty()
    password: string;
}