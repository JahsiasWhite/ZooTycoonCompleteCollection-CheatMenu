# Zoo Tycoon Memory Offsets

Detailed breakdown of some memory structures, offsets, and known default values.

## Base Game Config (`0x00238048`)

| Offset | Field Name                | Type  | Notes                | Default Value |
| ------ | ------------------------- | ----- | -------------------- | ------------- |
| 0x006C | AngryAnimalsSickChange    | int32 |                      | 0             |
| 0x0070 | PctSick                   | int32 |                      | 0             |
| 0x0074 | PctProtestors             | float |                      | 17.45         |
| 0x0078 | AngryHungryGuestsChange   | int32 |                      | 1000          |
| 0x007C | PctHungry                 | float |                      |               |
| 0x0080 | AngryThirstyGuestsChange  | float |                      | 0.3           |
| 0x0084 | PctThirsty                | float |                      | 0.3           |
| 0x0088 | AngryBathroomGuestsChange | float |                      |               |
| 0x008C | PctBathroom               | float |                      | 0.2           |
| 0x0090 | AngrySouvenirGuestsChange | float |                      |               |
| 0x0094 | PctSouvenir               | float |                      | 0.2           |
| 0x0098 | AngryRemoveAnimalChange   | float |                      |               |
| 0x009C | AngryTiredGuestsChange    | float |                      | 0.3           |
| 0x00A0 | PctTired                  | float |                      |               |
| 0x00A4 | AngryTrashGuestsChange    | float |                      | 0.7           |
| 0x00A8 | PctTrash                  | float |                      |               |
| 0x00AC | CreateGuestChanceVeryLow  | float |                      |               |
| 0x00B0 | CreateGuestChanceLow      | float |                      | 0.3           |
| 0x00B4 | CreateGuestChanceMed      | float |                      |               |
| 0x00B8 | CreateGuestChanceHigh     | float |                      | 0.4           |
| 0x00BC | CreateGuestChanceVeryHigh | int32 |                      | 3             |
| 0x00C0 | LoanAvailable             | int32 |                      | 5             |
| 0x00C4 | HighZooValueChange        | int32 |                      | 25            |
| 0x1154 | MinAdultAdmissionPrice    | int32 | Minimum ticket price | 0             |
| 0x1158 | MaxAdultAdmissionPrice    | int32 | Maximum ticket price | 100           |
| 0x115C | PricingFactor             | float |                      | 0.75          |
| 0x1160 | DonationFactor            | float |                      | 0             |
| 0x1164 | BuildingUseCostDefault    | int32 |                      | 3             |
| 0x1168 | BuildingUseCostMax        | int32 |                      | 30            |
| 0x116C | ZooDooRecyclingAmount     | int32 |                      | 50            |

## Random

| Address    | Field Name | Notes | Default Value |
| ---------- | ---------- | ----- | ------------- |
| 0x00238048 | maxGuests  |       | 1000          |

## Fence Config - Multiple types

| Field Name     | Notes                                             |
| -------------- | ------------------------------------------------- |
| Strength       | If low enough, animals can break straight through |
| Life           | Initial health                                    |
| DecayedLife    |                                                   |
| DecayDelta     |                                                   |
| Height         |                                                   |
| Selectable     |                                                   |
| SeeThrough     |                                                   |
| NoDrawWater    |                                                   |
| IsJumpable     | Animal can jump over                              |
| IsClimbable    | Animal can climb                                  |
| IsElectrified  | Electric fence                                    |
| Indestructible | Cannot be broken                                  |
| IsShowFence    |                                                   |

## Tank Config

| Field Name                | Default Value | Notes                    |
| ------------------------- | ------------- | ------------------------ |
| saltWater                 | 1.50          | Salt concentration       |
| freshWater                | 1.00          | Freshwater concentration |
| wallHeightPriceDivisor    | 5             |                          |
| initialSink               | 4             |                          |
| initialSinkShow           | 8             |                          |
| initialHeight             | 5             |                          |
| initialHeightShow         | 9             |                          |
| initialWaterLevel         | 0             |                          |
| initialFillState          | 1             |                          |
| initialSalinity           | 100           |                          |
| initialTemperature        | 0             |                          |
| maximumTankHeight         | 20            |                          |
| waterOffset               | -1            |                          |
| tankTerrain               | 2             |                          |
| tankTerrainShow           | 0.01          |                          |
| initialWaterPurity        | 100           |                          |
| murkyWaterPurity          | 60            |                          |
| veryMurkyWaterPurity      | 0.13          |                          |
| extremelyMurkyWaterPurity | 0.13          |                          |
| waterPurityDecayTime      | 30000         |                          |

## Shows

| Field Name              | Default Value | Notes |
| ----------------------- | ------------- | ----- |
| returnToKeeperThreshold |               |       |
| infrequentShowInterval  |               |       |
| frequentShowInterval    |               |       |
| continuousShowInterval  |               |       |
| showAdmissionIncrement  |               |       |
| minShowAdmission        |               |       |
| startSound              |               |       |
| endSound                |               |       |
| maxLength               |               |       |
