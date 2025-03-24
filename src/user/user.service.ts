import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { ILike, Like, Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UserSignUpDto } from './dto/user-signup.dto';
import {
  BadRequestResponse,
  InternalServerErrorReponse,
  NotFoundResponse,
  SigninResponse,
  SuccessResponse,
} from 'src/constants/reponse.constants';
import { compare, hash } from 'bcrypt';
import { UserSignInDto } from './dto/user-signin.dto';
import { sign, verify } from 'jsonwebtoken';
import { UserChangePassDto } from './dto/user-changePass.dto';
import { UserRefreshDto } from './dto/user-refresh.dto';
import { ApiTags } from '@nestjs/swagger';
import { UserResetPasswordDto } from './dto/user-resetPass.dto';
import { MailService } from 'src/mail/mail.service';
import { Role } from 'src/utilities/common/user-role.enum';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private mailService: MailService,
  ) {}

  async signup(body: UserSignUpDto) {
    try {
      const emailExists = await this.findUserByEmail(body.email);
      const userExist = await this.userRepository.findOneBy({
        username: body.username,
      });
      if (userExist) return BadRequestResponse('Sser already exists');
      if (emailExists) return BadRequestResponse('Email already exists');
      body.password = await hash(body.password, 10);
      const user = this.userRepository.create(body);
      await this.userRepository.save(user);
      return SuccessResponse();
    } catch (error) {
      console.log(error);
      throw BadRequestResponse();
    }
  }

  async signin(body: UserSignInDto) {
    const userExists = await this.userRepository
      .createQueryBuilder('users')
      .addSelect('users.password')
      .where('users.username=:username', { username: body.username })
      .getOne();
    if (!userExists) return NotFoundResponse('User not found');
    const matchPassword = await compare(body.password, userExists.password);
    if (!matchPassword) return BadRequestResponse();
    delete userExists.password;
    return SigninResponse(
      await this.accessToken(userExists),
      await this.generateRefreshToken(userExists),
    );
  }

  async findAll(page: number) {
    try {
      if (page <= 0) {
        return BadRequestResponse('Page must be greater than zero');
      }
      const [users, total] = await this.userRepository.findAndCount({
        take: 10,
        skip: (page - 1) * 10 || 0,
      });
      if (!users && users.length <= 0) {
        return NotFoundResponse();
      }
      const currentPage = +page || 1;
      const totalPage = Math.ceil(total / 10);
      return SuccessResponse({ users, count: total, currentPage, totalPage });
    } catch (error) {
      return error.message;
    }
  }

  async findId(id: number) {
    const user = await this.userRepository.findOneBy({ id });
    if (user === null) {
      return NotFoundResponse();
    }
    return SuccessResponse(user);
  }

  async findName(name: string) {
    const user = await this.userRepository.find({
      where: [
        {
          lastName: ILike(`%${name}%`),
        },
        {
          firstName: ILike(`%${name}%`),
        },
      ],
    });
    if (user === null || user.length === 0) {
      return NotFoundResponse();
    }
    return SuccessResponse(user);
  }

  async updateUser(id: number, updateUserDto: UpdateUserDto) {
    const user = await this.userRepository.findOneBy({ id });
    if (user !== null) {
      await this.userRepository.update(id, updateUserDto);
      return SuccessResponse();
    }
    return NotFoundResponse();
  }

  async changePassword(id: number, password: UserChangePassDto) {
    const user = await this.userRepository.findOneBy({ id });
    if (user !== null) {
      password.password = await hash(password.password, 10);
      await this.userRepository.update(id, password);
      return SuccessResponse();
    }
    return NotFoundResponse();
  }

  async findUserByEmail(email: string) {
    return await this.userRepository.findOneBy({ email });
  }

  async accessToken(user: User) {
    const currentTimeInSeconds = Math.floor(Date.now() / 1000); // Get current time in seconds
    const expiresInSeconds = currentTimeInSeconds + (15 * 60); // 15 minutes
    return sign(
      {
        id: user.id,
        username: user.username,
        role: user.roles,
        password: user.password,
      },
      process.env.ACCESS_TOKEN_SECRET_KEY,
      { expiresIn: expiresInSeconds },
    );
  }

  async generateRefreshToken(user: User) {
    const currentTimeInSeconds = Math.floor(Date.now() / 1000); // Get current time in seconds
    const days = 7;
    const secondsInADay = 24 * 60 * 60;
    const expiresInSeconds = currentTimeInSeconds + (days * secondsInADay);
    return sign(
      {
        id: user.id,
        username: user.username,
        role: user.roles,
        password: user.password,
      },
      process.env.REFRESH_TOKEN_SECRET_KEY,
      { expiresIn: expiresInSeconds},
    );
  }

  async refreshToken(refreshToken: UserRefreshDto) {
    try {
      const { id } = <JwtPayload>(
        verify(refreshToken.refreshToken, process.env.REFRESH_TOKEN_SECRET_KEY)
      );
      const user = await this.findId(+id);
      if (!user) {
        throw new UnauthorizedException();
      }
      const accessToken = await this.accessToken(user['data']);
      return { accessToken };
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  async resetPassword(resetPassword: UserResetPasswordDto) {
    const userExist = await this.userRepository.findOneBy({
      email: resetPassword.email,
    });
    if (!userExist) {
      return NotFoundResponse('Email not exist');
    }
    await this.mailService.sendPasswordReset(userExist, resetPassword.email);
    return SuccessResponse();
  }

  async delete(id: number) {
    try {
      const user = await this.userRepository.findOneBy({ id: id });
      if (!user) {
        return NotFoundResponse('User not found');
      }
      await this.userRepository.softDelete({ id: id });
      return SuccessResponse('User deleted');
    } catch (error) {
      console.log(error);
      return BadRequestResponse();
    }
  }

  async getAllRoles() {
    try {
      if (Role == null) {
        return NotFoundResponse('Role not found');
      }
      return SuccessResponse(Role);
    } catch (error) {
      console.log(error);
      return BadRequestResponse();
    }
  }

  async createEmployee(body: UserSignUpDto, role: Role) {
    try {
      const emailExists = await this.findUserByEmail(body.email);
      const userExist = await this.userRepository.findOneBy({
        username: body.username,
      });
      if (userExist) return BadRequestResponse('User already exists');
      if (emailExists) return BadRequestResponse('Email already exists');
      body.password = await hash(body.password, 10);
      const user = this.userRepository.create(body);
      user.roles = role;
      await this.userRepository.save(user);
      return SuccessResponse();
    } catch (error) {
      console.log(error);
      throw BadRequestResponse();
    }
  }

  async updateRoleAdmin(id: number, role: Role, body: UpdateUserDto) {
    try {
      const userExist = await this.userRepository.findOneBy({ id: id });
      if (userExist) {
        userExist.roles = role;
        (userExist.email = body.email), (userExist.firstName = body.firstName);
        userExist.lastName = body.lastName;
        userExist.phoneNumber = body.phoneNumber;
        userExist.gender = body.gender;
        await this.userRepository.update(id, userExist);
        return SuccessResponse();
      }
      return NotFoundResponse('User not found');
    } catch (error) {
      console.log(error);
      return InternalServerErrorReponse();
    }
  }

  async resetPasswordViaToken(currentUser: User, password: UserChangePassDto) {
    try {
      const userExist = await this.userRepository.findOneBy({
        id: currentUser.id,
      });
      if (!userExist) {
        return NotFoundResponse('user not found');
      }
      userExist.password = await hash(password.password, 10);
      await this.userRepository.update(userExist.id, userExist);
      return SuccessResponse();
    } catch (error) {
      console.log(error);
      return InternalServerErrorReponse();
    }
  }
}
interface JwtPayload {
  id: string;
}
