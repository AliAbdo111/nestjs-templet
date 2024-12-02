import { Body, Controller, Get, HttpCode, HttpStatus, Post, Res } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { Public } from '../../decorators/public.decorator';
import { UserDto } from '../../common/dto/user-dto';
import { UserService } from '../user/user.service';
import { AuthService } from './auth.service';
import { LoginPayloadDto } from '../../common/dto/login-payload.dto';
import { UserLoginDto } from '../../common/dto/user-login.dto';
import { UserRegisterDto } from '../../common/dto/user-register.dto';
import { Response } from 'express';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(
    public readonly userService: UserService,
    public readonly authService: AuthService,
  ) { }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOkResponse({
    type: LoginPayloadDto,
    description: 'User infos',
  })
  async userLogin(
    @Body() userLoginDto: UserLoginDto,
  ): Promise<LoginPayloadDto> {
    const userEntity = await this.authService.validateUser(userLoginDto);

    const token = await this.authService.createToken(userEntity);

    return new LoginPayloadDto(userEntity.toDto(), token);
  }

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOkResponse({ type: UserDto, description: 'Register User' })
  async userRegister(
    @Body() userRegisterDto: UserRegisterDto,
  ): Promise<UserDto> {
    const createdUser = await this.userService.createUser(userRegisterDto);

    return createdUser.toDto();
  }
  @Public()

  @Get('/download-file')
  async downloadFile(@Res() res: Response) {
    const buffer = await this.authService.donwlaodFile()
    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': 'attachment; filename="file.pdf"',
      'Content-Length': buffer.length,
    });

    res.send(buffer);
  }

}