import { Body, Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { signInDTO, signUpDTO } from './dtos/auth';
import { AuthService } from './auth.service';
import { AuthGuard } from './auth.guard';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService) { }

    @Post('signup') //inscrever-se
    async signup(@Body() body: signUpDTO) {
        return this.authService.signup(body)
    }

    @Post('signin') //logar-se
    async signin(@Body() body: signInDTO) {
        return this.authService.signin(body)
    }

    @UseGuards(AuthGuard)
    @Get('me') //meu perfil
    async me(@Request() request) {
        return request.user
    }

}
