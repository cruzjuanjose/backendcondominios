// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

export interface JwtPayload {
  sub: number | bigint;
  username: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(username: string, password: string) {
    const user = await this.prisma.user_account.findUnique({
      where: { username },
    });

    if (!user || !user.is_active) {
      throw new UnauthorizedException('Usuario o contraseña inválidos');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password_hash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Usuario o contraseña inválidos');
    }

    const { password_hash, ...safeUser } = user as any;
    return safeUser;
  }

  async login(username: string, password: string) {
    const user = await this.validateUser(username, password);

    const payload: JwtPayload = {
      sub: user.user_id,
      username: user.username,
    };

    const accessToken = await this.jwtService.signAsync(payload);

    return {
      accessToken,
      user,
    };
  }
}
