//passar o Token dentro do header Authorization
import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { jwtConstants } from './constans';

@Injectable()
export class AuthGuard implements CanActivate {

    constructor(private jwtService: JwtService) { }

    // Verifica se o token está presente no header Authorization
    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);

        // Se o token não estiver presente, lança uma exceção UnauthorizedException
        if (!token) {
            throw new UnauthorizedException('Token not found');
        }

        try { // Tenta verificar se o token é válido
            const payload = await this.jwtService.verifyAsync(token, {
                secret: jwtConstants.secret
            });
            request['user'] = payload; // Adiciona o payload do token ao objeto request
        } catch (error) {
            throw new UnauthorizedException('Invalid token');
        }
        return true; // Se o token for válido, permite o acesso
    }

    // Verifica se o token é válido e se o usuário existe no banco de dados
    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers['authorization']?.split(' ') || [];
        return type === 'Bearer' ? token : undefined;

    }
}