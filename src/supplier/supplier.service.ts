import { Injectable } from '@nestjs/common';
import { CreateSupplierDto } from './dto/create-supplier.dto';
import { UpdateSupplierDto } from './dto/update-supplier.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Supplier } from './entities/supplier.entity';
import { Like, Repository } from 'typeorm';
import {
  BadRequestResponse,
  NotFoundResponse,
  SuccessResponse,
} from 'src/constants/reponse.constants';

@Injectable()
export class SupplierService {
  constructor(
    @InjectRepository(Supplier)
    private supplierRepository: Repository<Supplier>,
  ) {}
  async create(createSupplierDto: CreateSupplierDto) {
    try {
      const supplier = this.supplierRepository.create(createSupplierDto);
      await this.supplierRepository.save(supplier);
      return SuccessResponse();
    } catch (error) {
      return BadRequestResponse();
    }
  }

  async findAll() {
    try {
      const supplier = await this.supplierRepository.find({});
      if (!supplier || supplier.length === 0) {
        return NotFoundResponse();
      }
      return SuccessResponse(supplier);
    } catch (error) {
      return BadRequestResponse();
    }
  }

  async findOne(id: number) {
    const supplier = await this.supplierRepository.findOneBy({ id });
    if (supplier === null) {
      return NotFoundResponse();
    }
    return SuccessResponse(supplier);
  }

  async findName(name: string) {
    const supplier = await this.supplierRepository.find({
      where: {
        name: Like(`%${name}%`),
      },
    });
    if (supplier === null || supplier.length === 0) {
      return NotFoundResponse();
    }
    return SuccessResponse(supplier);
  }

  async update(id: number, updateSupplierDto: UpdateSupplierDto) {
    const supplier = await this.supplierRepository.findOneBy({ id });
    if (supplier != null) {
      await this.supplierRepository.update(id, updateSupplierDto);
      return SuccessResponse();
    }
    return NotFoundResponse();
  }
}