import { MiddlewareConsumer, Module, RequestMethod } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { dataSourceOptions } from 'db/data-source';
import { UserModule } from './user/user.module';
import { CurrentUserMiddleware } from './utilities/middlewares/current-user.middlewares';
import { ProductModule } from './product/product.module';
import { CategoryModule } from './category/category.module';
import { SupplierModule } from './supplier/supplier.module';
import { RecipientDetailModule } from './recipient-detail/recipient-detail.module';
import { RecipientBillModule } from './recipient-bill/recipient-bill.module';
import { SaleModule } from './sale/sale.module';
import { OrderDetailModule } from './order_detail/order_detail.module';
import { OrderModule } from './order/order.module';
import { RateModule } from './rate/rate.module';
import { CartModule } from './cart/cart.module';
import { CartDetailModule } from './cart_detail/cart_detail.module';
import { MailModule } from './mail/mail.module';
import { AddressModule } from './address/address.module';
import { StatisticsModule } from './statistics/statistics.module';

@Module({
  imports: [
    TypeOrmModule.forRoot(dataSourceOptions),
    UserModule,
    ProductModule,
    CategoryModule,
    SupplierModule,
    RecipientDetailModule,
    RecipientBillModule,
    SaleModule,
    OrderDetailModule,
    OrderModule,
    RateModule,
    CartModule,
    CartDetailModule,
    MailModule,
    AddressModule,
    StatisticsModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(CurrentUserMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
