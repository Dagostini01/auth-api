import * as bcrypt from 'bcrypt';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { signInDTO, signUpDTO } from './dtos/auth';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

    constructor(private prismaService: PrismaService, private jwtService: JwtService) { }

    async signup(data: signUpDTO) { //inscrever-se

        const userAlreadyExists = await this.prismaService.user.findUnique({ //esse email tem cadastrado?
            where: {
                email: data.email
            },
        })

        if (userAlreadyExists) { //se existir, nao pode cadastrar novamente
            throw new UnauthorizedException('User already exists!')
        }

        const hashedPassword = await bcrypt.hash(data.password, 10) //criptografar a senha
        const user = await this.prismaService.user.create({ data: { ...data, password: hashedPassword } }) //se nao existir, cria o usuario

        return {
            id: user.id,
            name: user.name,
            email: user.email
        }
    }

    async signin(data: signInDTO) {

        const user = await this.prismaService.user.findUnique({ //esse email tem cadastrado?
            where: {
                email: data.email
            },
        })

        if (!user) { //se nao existir, nao pode logar
            throw new UnauthorizedException('Invalid credentials!')
        }

        const isPasswordValid = await bcrypt.compare(data.password, user.password) //verifica se a senha esta correta
        if (!isPasswordValid) { //se a senha estiver incorreta, nao pode logar
            throw new UnauthorizedException('Invalid credentials!')
        }

        const accessToken = this.jwtService.signAsync({ //gera o token de acesso
            id: user.id,
            name: user.name,
            email: user.email
        })

        return accessToken //retorna o token de acesso
    }
}