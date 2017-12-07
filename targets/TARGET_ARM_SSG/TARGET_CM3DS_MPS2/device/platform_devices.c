/*
 * Copyright (c) 2017-2018 ARM Limited
 *
 * Licensed under the Apache License Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "platform_devices.h"
#include "SMM_MPS2.h"

/* ARM CMSDK Timer driver structures */
#ifdef ARM_CMSDK_TIMER0
static const struct timer_cmsdk_dev_cfg_t CMSDK_TIMER0_DEV_CFG = {
    .base = CMSDK_TIMER0_BASE};
static struct timer_cmsdk_dev_data_t CMSDK_TIMER0_DEV_DATA = {
    .is_initialized = 0};
struct timer_cmsdk_dev_t CMSDK_TIMER0_DEV = {&(CMSDK_TIMER0_DEV_CFG),
                                           &(CMSDK_TIMER0_DEV_DATA)};
#endif

#ifdef ARM_CMSDK_TIMER1
static const struct timer_cmsdk_dev_cfg_t CMSDK_TIMER1_DEV_CFG = {
    .base = CMSDK_TIMER1_BASE};
static struct timer_cmsdk_dev_data_t CMSDK_TIMER1_DEV_DATA = {
    .is_initialized = 0};
struct timer_cmsdk_dev_t CMSDK_TIMER1_DEV = {&(CMSDK_TIMER1_DEV_CFG),
                                           &(CMSDK_TIMER1_DEV_DATA)};
#endif

/* ARM GPIO driver structures */
#ifdef ARM_GPIO0
static const struct arm_gpio_dev_cfg_t ARM_GPIO0_DEV_CFG = {
  .base = CMSDK_GPIO0_BASE};
static struct arm_gpio_dev_data_t ARM_GPIO0_DEV_DATA = {
    .state = 0,
    .port_mask = DEFAULT_PORT_MASK};
struct arm_gpio_dev_t ARM_GPIO0_DEV = {&(ARM_GPIO0_DEV_CFG),
                                       &(ARM_GPIO0_DEV_DATA)};
#endif /* ARM_GPIO0 */

#ifdef ARM_GPIO1
static const struct arm_gpio_dev_cfg_t ARM_GPIO1_DEV_CFG = {
  .base = CMSDK_GPIO1_BASE};
static struct arm_gpio_dev_data_t ARM_GPIO1_DEV_DATA = {
    .state = 0,
    .port_mask = DEFAULT_PORT_MASK};
struct arm_gpio_dev_t ARM_GPIO1_DEV = {&(ARM_GPIO1_DEV_CFG),
                                       &(ARM_GPIO1_DEV_DATA)};
#endif /* ARM_GPIO1 */

#ifdef ARM_GPIO2
static const struct arm_gpio_dev_cfg_t ARM_GPIO2_DEV_CFG = {
  .base = CMSDK_GPIO2_BASE};
static struct arm_gpio_dev_data_t ARM_GPIO2_DEV_DATA = {
    .state = 0,
    .port_mask = DEFAULT_PORT_MASK};
struct arm_gpio_dev_t ARM_GPIO2_DEV = {&(ARM_GPIO2_DEV_CFG),
                                       &(ARM_GPIO2_DEV_DATA)};
#endif /* ARM_GPIO2 */

#ifdef ARM_GPIO3
static const struct arm_gpio_dev_cfg_t ARM_GPIO3_DEV_CFG = {
  .base = CMSDK_GPIO3_BASE};
static struct arm_gpio_dev_data_t ARM_GPIO3_DEV_DATA = {
    .state = 0,
    .port_mask = DEFAULT_PORT_MASK};
struct arm_gpio_dev_t ARM_GPIO3_DEV = {&(ARM_GPIO3_DEV_CFG),
                                       &(ARM_GPIO3_DEV_DATA)};
#endif /* ARM_GPIO3 */

/* ARM MPS2 IO FPGAIO driver structures */
#ifdef ARM_MPS2_IO_FPGAIO
static const struct arm_mps2_io_dev_cfg_t ARM_MPS2_IO_FPGAIO_DEV_CFG = {
  .base = MPS2_FPGAIO_BASE,
  .type = ARM_MPS2_IO_TYPE_FPGAIO};
struct arm_mps2_io_dev_t ARM_MPS2_IO_FPGAIO_DEV =
                                                {&(ARM_MPS2_IO_FPGAIO_DEV_CFG)};
#endif /* ARM_MPS2_IO_FPGAIO */

/* ARM MPS2 IO SCC driver structures */
#ifdef ARM_MPS2_IO_SCC
static const struct arm_mps2_io_dev_cfg_t ARM_MPS2_IO_SCC_DEV_CFG = {
  /*
   * MPS2 IO SCC and FPGAIO registers have similar structure
   * with 4 byte offset addresses.
   */
  .base = MPS2_SCC_BASE + 4,
  .type = ARM_MPS2_IO_TYPE_SCC};
struct arm_mps2_io_dev_t ARM_MPS2_IO_SCC_DEV = {&(ARM_MPS2_IO_SCC_DEV_CFG)};
#endif /* ARM_MPS2_IO_SCC */

/* ARM SPI driver structure */
#ifdef ARM_SPI0
static const struct spi_pl022_dev_cfg_t SPI0_PL022_DEV_CFG = {
    .base = MPS2_SSP0_BASE,
    .default_ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = SPI_PL022_CFG_FRF_MOT,
       .word_size = 8,
       .bit_rate = DEFAULT_SPI_SPEED_HZ
    }};
static struct spi_pl022_dev_data_t SPI0_PL022_DEV_DATA = {
    .state = 0,
    .sys_clk = 0,
    .ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = 0,
       .word_size = 0,
       .bit_rate = 0
     }};
struct spi_pl022_dev_t SPI0_PL022_DEV = {&(SPI0_PL022_DEV_CFG),
                                           &(SPI0_PL022_DEV_DATA)};
#endif /* ARM_SPI0 */

#ifdef ARM_SPI1
static const struct spi_pl022_dev_cfg_t SPI1_PL022_DEV_CFG = {
    .base = MPS2_SSP1_BASE,
    .default_ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = SPI_PL022_CFG_FRF_MOT,
       .word_size = 8,
       .bit_rate = DEFAULT_SPI_SPEED_HZ
    }};
static struct spi_pl022_dev_data_t SPI1_PL022_DEV_DATA = {
    .state = 0,
    .sys_clk = 0,
    .ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = 0,
       .word_size = 0,
       .bit_rate = 0
     }};
struct spi_pl022_dev_t SPI1_PL022_DEV = {&(SPI1_PL022_DEV_CFG),
                                           &(SPI1_PL022_DEV_DATA)};
#endif /* ARM_SPI1 */

#ifdef ARM_SPI2
static const struct spi_pl022_dev_cfg_t SPI2_PL022_DEV_CFG = {
    .base = MPS2_SSP2_BASE,
    .default_ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = SPI_PL022_CFG_FRF_MOT,
       .word_size = 8,
       .bit_rate = DEFAULT_SPI_SPEED_HZ
    }};
static struct spi_pl022_dev_data_t SPI2_PL022_DEV_DATA = {
    .state = 0,
    .sys_clk = 0,
    .ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = 0,
       .word_size = 0,
       .bit_rate = 0
     }};
struct spi_pl022_dev_t SPI2_PL022_DEV = {&(SPI2_PL022_DEV_CFG),
                                           &(SPI2_PL022_DEV_DATA)};
#endif /* ARM_SPI2 */

#ifdef ARM_SPI3
static const struct spi_pl022_dev_cfg_t SPI3_PL022_DEV_CFG = {
    .base = MPS2_SSP3_BASE,
    .default_ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = SPI_PL022_CFG_FRF_MOT,
       .word_size = 8,
       .bit_rate = DEFAULT_SPI_SPEED_HZ
    }};
static struct spi_pl022_dev_data_t SPI3_PL022_DEV_DATA = {
    .state = 0,
    .sys_clk = 0,
    .ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = 0,
       .word_size = 0,
       .bit_rate = 0
     }};
struct spi_pl022_dev_t SPI3_PL022_DEV = {&(SPI3_PL022_DEV_CFG),
                                           &(SPI3_PL022_DEV_DATA)};
#endif /* ARM_SPI3 */

#ifdef ARM_SPI4
static const struct spi_pl022_dev_cfg_t SPI4_PL022_DEV_CFG = {
    .base = MPS2_SSP4_BASE,
    .default_ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = SPI_PL022_CFG_FRF_MOT,
       .word_size = 8,
       .bit_rate = DEFAULT_SPI_SPEED_HZ
    }};
static struct spi_pl022_dev_data_t SPI4_PL022_DEV_DATA = {
    .state = 0,
    .sys_clk = 0,
    .ctrl_cfg = {
       .spi_mode = SPI_PL022_MASTER_SELECT,
       .frame_format = 0,
       .word_size = 0,
       .bit_rate = 0
     }};
struct spi_pl022_dev_t SPI4_PL022_DEV = {&(SPI4_PL022_DEV_CFG),
                                           &(SPI4_PL022_DEV_DATA)};
#endif /* ARM_SPI4 */
