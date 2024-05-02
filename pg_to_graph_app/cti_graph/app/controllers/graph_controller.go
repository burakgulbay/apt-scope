package controllers

import (
	"cti_graph/app/models"
	"cti_graph/fileops"
	"cti_graph/pkg/repositories"
	"cti_graph/pkg/utils"
	"cti_graph/platform/database"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func ImportAbusechBotnetIp(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetAbusechBotnetIpBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		fmt.Println(iocList[i].IoC)
		if iocList[i].IoC != "" {

			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateAbusechBotnetIpBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			} else {
				fmt.Println("Ioc zaten var: ", iocList[i].IoC)
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("abusech_botnet_ip_blacklist")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("abusech_botnet_ip_blacklist")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("abusech_botnet_ip_blacklist", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportAbusechSslBlacklist(c *fiber.Ctx) error {

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetAbusechSslBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateAbusechSslBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("abusech_ssl_blacklist")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("abusech_ssl_blacklist")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("abusech_ssl_blacklist", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportCiarmyBadguysBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetCiarmyBadguysBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateCiarmyBadguysBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("ciarmy_badguys")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("ciarmy_badguys")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("ciarmy_badguys", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportDarklistBacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetDarklistBacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateDarklistBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("darklist_blacklisted_ip_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("darklist_blacklisted_ip_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("darklist_blacklisted_ip_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportDshieldTop10Blacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetDshieldTop10Blacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {

			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateDshieldTop10Blacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("dshield_top10")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("dshield_top10")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("dshield_top10", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportEmergingThreatsCompromisedBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetEmergingThreatsCompromisedBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)

			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateEmergingThreatsCompromisedBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("emergingthreats_compromised_ips")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("emergingthreats_compromised_ips")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("emergingthreats_compromised_ips", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportFeodoTrackerBotnetBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetFeodoTrackerBotnetBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateFeodoTrackerBotnetBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("feodotracker_botnet_ip_blacklist")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("feodotracker_botnet_ip_blacklist")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("feodotracker_botnet_ip_blacklist", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubAnudeepAdServers(c *fiber.Ctx) error {

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubAnudeepAdServers(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubAnudeepAdServers(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("github_anudeep_ad_servers")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_anudeep_ad_servers")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_anudeep_ad_servers", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubAnudeepCoinMiners(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubAnudeepCoinMiners(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubAnudeepCoinMiners(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			platformExist, err := repositories.GraphRepo.FindReporterPlatform("github_anudeep_coin_miner")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if platformExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_anudeep_coin_miner")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_anudeep_coin_miner", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubAnudeepFacebook(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubAnudeepFacebook(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubAnudeepFacebook(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_anudeep_facebook")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_anudeep_facebook")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_anudeep_facebook", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubBlocklistProjectAbuseBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubBlocklistProjectAbuseBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubBlocklistProjectAbuseBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_blocklistproject_abuse_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_blocklistproject_abuse_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_blocklistproject_abuse_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubBlocklistProjectAdsBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubBlocklistProjectAdsBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubBlocklistProjectAdsBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_blocklistproject_ads_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_blocklistproject_ads_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_blocklistproject_ads_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubBlocklistProjectCryptoBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubBlocklistProjectCryptoBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubBlocklistProjectCryptoBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_blocklistproject_crypto_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_blocklistproject_crypto_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_blocklistproject_crypto_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubBlocklistProjectDrugsBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubBlocklistProjectDrugsBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubBlocklistProjectDrugsBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_blocklistproject_drugs_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_blocklistproject_drugs_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_blocklistproject_drugs_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubBlocklistProjectFacebookBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubBlocklistProjectFacebookBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubBlocklistProjectFacebookBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_blocklistproject_facebook_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_blocklistproject_facebook_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_blocklistproject_facebook_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubBlocklistProjectFraudBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubBlocklistProjectFraudBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubBlocklistProjectFraudBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_blocklistproject_fraud_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_blocklistproject_fraud_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_blocklistproject_fraud_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubBlocklistProjectGamblingBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubBlocklistProjectGamblingBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubBlocklistProjectGamblingBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_blocklistproject_gambling_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_blocklistproject_gambling_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_blocklistproject_gambling_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubEtherAdressLookupDomainBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubEtherAdressLookupDomainBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubEtherAdressLookupDomainBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_ether_address_lookup_domains")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_ether_address_lookup_domains")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_ether_address_lookup_domains", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubEtherAdressLookupURIBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubEtherAdressLookupURIBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubEtherAdressLookupURIBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_ether_address_lookup_uri")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_ether_address_lookup_uri")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_ether_address_lookup_uri", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportGithubAntiSocialEngineer(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetGithubAntiSocialEngineer(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateGithubAntiSocialEngineer(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("github_the_anti_social_engineer")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("github_the_anti_social_engineer")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("github_the_anti_social_engineer", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportMalwareBazaarHashBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetMalwareBazaarHashBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateMalwareBazaarHashBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("malware_bazaar_hash_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("malware_bazaar_hash_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("malware_bazaar_hash_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportPublicDnsInfoNameserversAll(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetPublicDnsInfoNameserversAll(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			dnsExist, err := repositories.GraphRepo.FindDns(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if dnsExist == nil {
				err = repositories.GraphRepo.CreatePublicDnsInfoNameservers(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("public_dns_info_nameservers_all")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("public_dns_info_nameservers_all")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToDns("public_dns_info_nameservers_all", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportThreatfoxBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetThreatfoxBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateThreatfoxBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("threatfox_ioc_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("threatfox_ioc_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("threatfox_ioc_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportTorIp(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetTorIp(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateTorIp(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("tor_ip_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("tor_ip_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToTor("tor_ip_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportUrlHausAbuseHostBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetUrlHausAbuseHostBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateUrlHausAbuseHostBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("urlhaus_abuse_hosts")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("urlhaus_abuse_hosts")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("urlhaus_abuse_hosts", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportUrlHausDistributingMalware(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetUrlHausDistributingMalware(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateUrlHausDistributingMalware(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("urlhaus_distributing_malware")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("urlhaus_distributing_malware")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("urlhaus_distributing_malware", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportUsomMaliciousUrlBlacklist(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	iocList, err := db.GetUsomMaliciousUrlBlacklist(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range iocList {
		if iocList[i].IoC != "" {
			fmt.Println(iocList[i].IoC)
			iocExist, err := repositories.GraphRepo.FindIoC(iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if iocExist == nil {
				err = repositories.GraphRepo.CreateUsomMaliciousUrlBlacklist(iocList[i])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			ipExist, err := repositories.GraphRepo.FindReporterPlatform("usom_malicious_url_list")
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if ipExist == nil {
				err = repositories.GraphRepo.CreateReporterPlatform("usom_malicious_url_list")
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeReporterPlatformToIoC("usom_malicious_url_list", iocList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportDomainToIp(c *fiber.Ctx) error {

	var firstParameterExistsInGraph, secondParameterExistsInGraph *models.CyberIoC

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	domainToIpList, err := db.GetDomainToIpList(relationshipImportRequest.Offset)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range domainToIpList {

		// domainToIpList[i].Domain gerçekten domain mi kontrol edelim.
		// domainToIpList[i].Ip gerçekten ip mi kontrol edelim.
		fmt.Println(domainToIpList[i].Domain, " - ", domainToIpList[i].Ip)

		firstParameterActualType := utils.ClassifyIoC(domainToIpList[i].Domain)
		secondParameterActualType := utils.ClassifyIoC(domainToIpList[i].Ip)

		if domainToIpList[i].Domain != "" {
			firstParameterExistsInGraph, err = repositories.GraphRepo.FindNode(domainToIpList[i].Domain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if firstParameterExistsInGraph == nil {

				if firstParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(domainToIpList[i].Domain)
				} else if firstParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(domainToIpList[i].Domain)
				} else if firstParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(domainToIpList[i].Domain)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(domainToIpList[i].Domain)
				}

				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		if domainToIpList[i].Ip != "" {
			secondParameterExistsInGraph, err = repositories.GraphRepo.FindNode(domainToIpList[i].Ip)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if secondParameterExistsInGraph == nil {

				if secondParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(domainToIpList[i].Ip)
				} else if secondParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(domainToIpList[i].Ip)
				} else if secondParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(domainToIpList[i].Ip)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(domainToIpList[i].Ip)
				}
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}
		if domainToIpList[i].Domain != "" && domainToIpList[i].Ip != "" {
			err = repositories.GraphRepo.MergeDomainToIp(&domainToIpList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportDomainToSubdomain(c *fiber.Ctx) error {

	var firstParameterExistsInGraph, secondParameterExistsInGraph *models.CyberIoC

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	domainToSubdomainList, err := db.GetDomainToSubdomainList(relationshipImportRequest.Offset)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range domainToSubdomainList {

		// domainToSubdomainList[i].Domain gerçekten domain mi kontrol edelim
		// domainToSubdomainList[i].Subdomain gerçekten subdomain mi kontrol edelim
		fmt.Println(domainToSubdomainList[i].Domain, " - ", domainToSubdomainList[i].Subdomain)
		firstParameterActualType := utils.ClassifyIoC(domainToSubdomainList[i].Domain)
		secondParameterActualType := utils.ClassifyIoC(domainToSubdomainList[i].Subdomain)

		if domainToSubdomainList[i].Domain != "" {
			firstParameterExistsInGraph, err = repositories.GraphRepo.FindNode(domainToSubdomainList[i].Domain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if firstParameterExistsInGraph == nil {

				if firstParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(domainToSubdomainList[i].Domain)
				} else if firstParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(domainToSubdomainList[i].Domain)
				} else if firstParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(domainToSubdomainList[i].Domain)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(domainToSubdomainList[i].Domain)
				}
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		if domainToSubdomainList[i].Subdomain != "" {
			secondParameterExistsInGraph, err = repositories.GraphRepo.FindNode(domainToSubdomainList[i].Subdomain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if secondParameterExistsInGraph == nil {

				if secondParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(domainToSubdomainList[i].Subdomain)
				} else if secondParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(domainToSubdomainList[i].Subdomain)
				} else if secondParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(domainToSubdomainList[i].Subdomain)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(domainToSubdomainList[i].Subdomain)
				}
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		if domainToSubdomainList[i].Domain != "" && domainToSubdomainList[i].Subdomain != "" {
			err = repositories.GraphRepo.MergeDomainToSubdomain(&domainToSubdomainList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportSubdomainToIp(c *fiber.Ctx) error {

	var firstParameterExistsInGraph, secondParameterExistsInGraph *models.CyberIoC

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	subdomainToIpList, err := db.GetSubdomainToIpList(relationshipImportRequest.Offset)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range subdomainToIpList {

		// subdomainToIpList[i].Subdomain gerçekten subdomain mi kontrol edelim.
		// subdomainToIpList[i].Ip gerçekten ip mi kontrol edelim.
		fmt.Println(subdomainToIpList[i].Subdomain, " - ", subdomainToIpList[i].Ip)
		firstParameterActualType := utils.ClassifyIoC(subdomainToIpList[i].Subdomain)
		secondParameterActualType := utils.ClassifyIoC(subdomainToIpList[i].Ip)

		if subdomainToIpList[i].Subdomain != "" {
			firstParameterExistsInGraph, err = repositories.GraphRepo.FindNode(subdomainToIpList[i].Subdomain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if firstParameterExistsInGraph == nil {

				if firstParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(subdomainToIpList[i].Subdomain)
				} else if firstParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(subdomainToIpList[i].Subdomain)
				} else if firstParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(subdomainToIpList[i].Subdomain)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(subdomainToIpList[i].Subdomain)
				}

				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		if subdomainToIpList[i].Ip != "" {
			secondParameterExistsInGraph, err = repositories.GraphRepo.FindNode(subdomainToIpList[i].Ip)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if secondParameterExistsInGraph == nil {

				if secondParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(subdomainToIpList[i].Ip)
				} else if secondParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(subdomainToIpList[i].Ip)
				} else if secondParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(subdomainToIpList[i].Ip)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(subdomainToIpList[i].Ip)
				}

				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}
		if subdomainToIpList[i].Subdomain != "" && subdomainToIpList[i].Ip != "" {
			err = repositories.GraphRepo.MergeSubdomainToIp(&subdomainToIpList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportUrlToDomain(c *fiber.Ctx) error {

	var firstParameterExistsInGraph, secondParameterExistsInGraph *models.CyberIoC

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	urlToDomainList, err := db.GetUrlToDomainList(relationshipImportRequest.Offset)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range urlToDomainList {

		// urlToDomainList[i].Url gerçekten url mi kontrol edelim.
		// urlToDomainList[i].Domain gerçekten domain mi kontrol edelim.
		fmt.Println(urlToDomainList[i].Url, " - ", urlToDomainList[i].Domain)

		firstParameterActualType := utils.ClassifyIoC(urlToDomainList[i].Url)
		// secondParameterActualType := utils.ClassifyIoC(urlToDomainList[i].Domain)
		secondParameterActualType := utils.ClassifyIoC(utils.GetDomainOfUrl(urlToDomainList[i].Url))

		if urlToDomainList[i].Url != "" {
			firstParameterExistsInGraph, err = repositories.GraphRepo.FindNode(urlToDomainList[i].Url)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if firstParameterExistsInGraph == nil {

				if firstParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(urlToDomainList[i].Url)
				} else if firstParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(urlToDomainList[i].Url)
				} else if firstParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(urlToDomainList[i].Url)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(urlToDomainList[i].Url)
				}

				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		actualDomain := utils.GetDomainOfUrl(urlToDomainList[i].Url)
		if urlToDomainList[i].Domain != "" {

			secondParameterExistsInGraph, err = repositories.GraphRepo.FindNode(actualDomain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if secondParameterExistsInGraph == nil {

				if secondParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(actualDomain)
				} else if secondParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(actualDomain)
				} else if secondParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(actualDomain)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(actualDomain)
				}

				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		if urlToDomainList[i].Url != "" && actualDomain != "" {
			err = repositories.GraphRepo.MergeUrlToDomain(urlToDomainList[i].Url, actualDomain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportUrlToIp(c *fiber.Ctx) error {

	var firstParameterExistsInGraph, secondParameterExistsInGraph *models.CyberIoC

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	urlToIpList, err := db.GetUrlToIpList(relationshipImportRequest.Offset)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range urlToIpList {

		// urlToIpList[i].Url gerçekten url mi kontrol edelim.
		// urlToIpList[i].Ip gerçekten ip mi kontrol edelim.

		fmt.Println(urlToIpList[i].Url, " - ", urlToIpList[i].Ip)

		firstParameterActualType := utils.ClassifyIoC(urlToIpList[i].Url)
		secondParameterActualType := utils.ClassifyIoC(urlToIpList[i].Ip)

		if urlToIpList[i].Url != "" {
			firstParameterExistsInGraph, err = repositories.GraphRepo.FindNode(urlToIpList[i].Url)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			if firstParameterExistsInGraph == nil {

				if firstParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(urlToIpList[i].Url)
				} else if firstParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(urlToIpList[i].Url)
				} else if firstParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(urlToIpList[i].Url)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(urlToIpList[i].Url)
				}

				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		secondParameterExistsInGraph, err = repositories.GraphRepo.FindNode(urlToIpList[i].Ip)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		if secondParameterExistsInGraph == nil {
			if secondParameterActualType == "domain" {
				err = repositories.GraphRepo.CreateDomain(urlToIpList[i].Ip)
			} else if secondParameterActualType == "ip" {
				err = repositories.GraphRepo.CreateIp(urlToIpList[i].Ip)
			} else if secondParameterActualType == "subdomain" {
				err = repositories.GraphRepo.CreateSubdomain(urlToIpList[i].Ip)
			} else { // firstParameterActualType == "url"
				err = repositories.GraphRepo.CreateUrl(urlToIpList[i].Ip)
			}

			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		if urlToIpList[i].Url != "" && urlToIpList[i].Ip != "" {
			err = repositories.GraphRepo.MergeUrlToIp(&urlToIpList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportUrlToSubdomain(c *fiber.Ctx) error {

	var firstParameterExistsInGraph, secondParameterExistsInGraph *models.CyberIoC

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	urlToSubdomainList, err := db.GetUrlToSubdomainList(relationshipImportRequest.Offset)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range urlToSubdomainList {

		// urlToSubdomainList[i].Url gerçekten url mi kontrol edelim.
		// urlToSubdomainList[i].Subdomain gerçekten subdomain mi kontrol edelim.

		fmt.Println(urlToSubdomainList[i].Url, " - ", urlToSubdomainList[i].Subdomain)

		firstParameterActualType := utils.ClassifyIoC(urlToSubdomainList[i].Url)
		secondParameterActualType := utils.ClassifyIoC(urlToSubdomainList[i].Subdomain)

		if urlToSubdomainList[i].Url != "" {
			firstParameterExistsInGraph, err = repositories.GraphRepo.FindNode(urlToSubdomainList[i].Url)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if firstParameterExistsInGraph == nil {

				if firstParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(urlToSubdomainList[i].Url)
				} else if firstParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(urlToSubdomainList[i].Url)
				} else if firstParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(urlToSubdomainList[i].Url)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(urlToSubdomainList[i].Url)
				}

				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		if urlToSubdomainList[i].Subdomain != "" {
			secondParameterExistsInGraph, err = repositories.GraphRepo.FindNode(urlToSubdomainList[i].Subdomain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if secondParameterExistsInGraph == nil {

				if secondParameterActualType == "domain" {
					err = repositories.GraphRepo.CreateDomain(urlToSubdomainList[i].Subdomain)
				} else if secondParameterActualType == "ip" {
					err = repositories.GraphRepo.CreateIp(urlToSubdomainList[i].Subdomain)
				} else if secondParameterActualType == "subdomain" {
					err = repositories.GraphRepo.CreateSubdomain(urlToSubdomainList[i].Subdomain)
				} else { // firstParameterActualType == "url"
					err = repositories.GraphRepo.CreateUrl(urlToSubdomainList[i].Subdomain)
				}

				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

		if urlToSubdomainList[i].Url != "" && urlToSubdomainList[i].Subdomain != "" {
			err = repositories.GraphRepo.MergeUrlToSubdomain(&urlToSubdomainList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportTwitter(c *fiber.Ctx) error {

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	twitterList, err := db.GetTweetPosts(relationshipImportRequest.Offset)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range twitterList {

		tweets, err := utils.UnmarshallTwitterPayload(twitterList[i].Payload)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		for k, _ := range tweets {
			iocExist, err := repositories.GraphRepo.FindNode(twitterList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			if iocExist == nil {
				err = repositories.GraphRepo.CreateDomain(twitterList[i].IoC)
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
			tweetIdExist, err := repositories.GraphRepo.FindTweet(tweets[k].ID)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if tweetIdExist == nil {
				err = repositories.GraphRepo.CreateTweet(tweets[k])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeIoCToTweet(twitterList[i].IoC, tweets[k])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			twitterUsernameExist, err := repositories.GraphRepo.FindTwitterUser(tweets[k].Username)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if twitterUsernameExist == nil {
				err = repositories.GraphRepo.CreateTwitterUsername(tweets[k].Username)
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeTweetToTwitterUsername(tweets[k].ID, tweets[k].Username)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

		}

	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})
}

func ImportDomainSslCertificate(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	domainSslCertificateList, err := db.GetDomainSslQueries(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range domainSslCertificateList {

		fmt.Println(domainSslCertificateList[i].IoC)

		sslProfileInfo, err := utils.UnmarshallSslPayload(domainSslCertificateList[i].Payload)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		domainExist, err := repositories.GraphRepo.FindNode(domainSslCertificateList[i].IoC)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		if domainExist == nil {
			err = repositories.GraphRepo.CreateDomain(domainSslCertificateList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for k, _ := range sslProfileInfo.SslPortInfos {

			sslHashExist, err := repositories.GraphRepo.FindSslCertificate(sslProfileInfo.SslPortInfos[k].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if sslHashExist == nil {
				err = repositories.GraphRepo.CreateSslCertificate(sslProfileInfo.SslPortInfos[k])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeDomainToSslCertificate(domainSslCertificateList[i].IoC, sslProfileInfo.SslPortInfos[k].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for j, _ := range sslProfileInfo.SslPortInfos {
			IdOfPortOfSSL, err := repositories.GraphRepo.CreatePortOfSSL(strconv.Itoa(sslProfileInfo.SslPortInfos[j].Port))
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergePortIdAndSslSha256(IdOfPortOfSSL, sslProfileInfo.SslPortInfos[j].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for m, _ := range sslProfileInfo.SslPortInfos {
			IdOfIssuerName, err := repositories.GraphRepo.CreateIssuerName(sslProfileInfo.SslPortInfos[m].Issuer.Name)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergeIssuerNameAndSslSha256(IdOfIssuerName, sslProfileInfo.SslPortInfos[m].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for n, _ := range sslProfileInfo.SslPortInfos {
			IdOfIssuerCountry, err := repositories.GraphRepo.CreateIssuerCountry(sslProfileInfo.SslPortInfos[n].Issuer.Country)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergeIssuerCountryAndSslSha256(IdOfIssuerCountry, sslProfileInfo.SslPortInfos[n].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for t, _ := range sslProfileInfo.SslPortInfos {
			IdOfIssuerOrganization, err := repositories.GraphRepo.CreateIssuerOrganization(sslProfileInfo.SslPortInfos[t].Issuer.Organization)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergeIssuerOrganizationAndSslSha256(IdOfIssuerOrganization, sslProfileInfo.SslPortInfos[t].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for u, _ := range sslProfileInfo.SslPortInfos {

			for cn, _ := range sslProfileInfo.SslPortInfos[u].CommonNames {

				commonName, err := repositories.GraphRepo.FindNode(sslProfileInfo.SslPortInfos[u].CommonNames[cn])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
				if commonName == nil {
					err = repositories.GraphRepo.CreateDomain(sslProfileInfo.SslPortInfos[u].CommonNames[cn])
					if err != nil {
						return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
							"error":   true,
							"message": err,
							"data":    nil,
						})
					}
				}

				err = repositories.GraphRepo.MergeDomainToSslCertificate(sslProfileInfo.SslPortInfos[u].CommonNames[cn], sslProfileInfo.SslPortInfos[u].Fingerprints.SHA256)
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportSubdomainSslCertificate(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	subdomainSslCertificateList, err := db.GetSubdomainSslQueries(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range subdomainSslCertificateList {

		fmt.Println(subdomainSslCertificateList[i].IoC)

		sslProfileInfo, err := utils.UnmarshallSslPayload(subdomainSslCertificateList[i].Payload)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		subdomainExist, err := repositories.GraphRepo.FindNode(subdomainSslCertificateList[i].IoC)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		if subdomainExist == nil {
			err = repositories.GraphRepo.CreateSubdomain(subdomainSslCertificateList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for k, _ := range sslProfileInfo.SslPortInfos {

			sslHashExist, err := repositories.GraphRepo.FindSslCertificate(sslProfileInfo.SslPortInfos[k].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if sslHashExist == nil {
				err = repositories.GraphRepo.CreateSslCertificate(sslProfileInfo.SslPortInfos[k])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeSubdomainToSslCertificate(subdomainSslCertificateList[i].IoC, sslProfileInfo.SslPortInfos[k].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for j, _ := range sslProfileInfo.SslPortInfos {
			IdOfPortOfSSL, err := repositories.GraphRepo.CreatePortOfSSL(strconv.Itoa(sslProfileInfo.SslPortInfos[j].Port))
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergePortIdAndSslSha256(IdOfPortOfSSL, sslProfileInfo.SslPortInfos[j].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for m, _ := range sslProfileInfo.SslPortInfos {
			IdOfIssuerName, err := repositories.GraphRepo.CreateIssuerName(sslProfileInfo.SslPortInfos[m].Issuer.Name)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergeIssuerNameAndSslSha256(IdOfIssuerName, sslProfileInfo.SslPortInfos[m].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for n, _ := range sslProfileInfo.SslPortInfos {
			IdOfIssuerCountry, err := repositories.GraphRepo.CreateIssuerCountry(sslProfileInfo.SslPortInfos[n].Issuer.Country)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergeIssuerCountryAndSslSha256(IdOfIssuerCountry, sslProfileInfo.SslPortInfos[n].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for t, _ := range sslProfileInfo.SslPortInfos {
			IdOfIssuerOrganization, err := repositories.GraphRepo.CreateIssuerOrganization(sslProfileInfo.SslPortInfos[t].Issuer.Organization)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergeIssuerOrganizationAndSslSha256(IdOfIssuerOrganization, sslProfileInfo.SslPortInfos[t].Fingerprints.SHA256)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for u, _ := range sslProfileInfo.SslPortInfos {

			for cn, _ := range sslProfileInfo.SslPortInfos[u].CommonNames {

				commonName, err := repositories.GraphRepo.FindNode(sslProfileInfo.SslPortInfos[u].CommonNames[cn])
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
				if commonName == nil {
					err = repositories.GraphRepo.CreateSubdomain(sslProfileInfo.SslPortInfos[u].CommonNames[cn])
					if err != nil {
						return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
							"error":   true,
							"message": err,
							"data":    nil,
						})
					}
				}

				err = repositories.GraphRepo.MergeSubdomainToSslCertificate(sslProfileInfo.SslPortInfos[u].CommonNames[cn], sslProfileInfo.SslPortInfos[u].Fingerprints.SHA256)
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}
		}

	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportDomainWhois(c *fiber.Ctx) error {
	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	domainWhoisList, err := db.GetDomainWhoisList(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range domainWhoisList {

		fmt.Println(domainWhoisList[i].DomainName)

		domainExist, err := repositories.GraphRepo.FindNode(domainWhoisList[i].DomainName)

		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		if domainExist == nil {
			err = repositories.GraphRepo.CreateDomain(domainWhoisList[i].DomainName)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		// WhoisDomain denen nesne aslında alt kırılımlarına bölünmeli.

		whoisExist, err := repositories.GraphRepo.FindWhoisDomain(domainWhoisList[i].Id)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		if whoisExist == nil {
			err = repositories.GraphRepo.CreateWhoisDomain(&domainWhoisList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		err = repositories.GraphRepo.MergeDomainToWhoisDomain(domainWhoisList[i].Id, domainWhoisList[i].DomainName)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "created successfully",
		"data":    nil,
	})

}

func ImportIpWhois(c *fiber.Ctx) error {

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	ipWhoisList, err := db.GetIpWhoisList(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range ipWhoisList {

		fmt.Println(ipWhoisList[i].IpAddress)

		ipExist, err := repositories.GraphRepo.FindNode(ipWhoisList[i].IpAddress)

		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		if ipExist == nil {
			err = repositories.GraphRepo.CreateIp(ipWhoisList[i].IpAddress)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		whoisExist, err := repositories.GraphRepo.FindWhoisIp(ipWhoisList[i].Id)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		if whoisExist == nil {
			err = repositories.GraphRepo.CreateWhoisIp(&ipWhoisList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		err = repositories.GraphRepo.MergeIpToWhoisIp(ipWhoisList[i].Id, ipWhoisList[i].IpAddress)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		if ipWhoisList[i].RouteOrigin != "" {
			asnExist, err := repositories.GraphRepo.FindAsn(ipWhoisList[i].RouteOrigin)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
			if asnExist == nil {
				err = repositories.GraphRepo.CreateAsn(ipWhoisList[i].RouteOrigin)
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			err = repositories.GraphRepo.MergeIpToAsn(ipWhoisList[i].IpAddress, ipWhoisList[i].RouteOrigin)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

		}

	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "created successfully",
		"data":    nil,
	})

}

func ImportIpPortScan(c *fiber.Ctx) error {

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	ipPortScanList, err := db.GetIpPortScanList(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range ipPortScanList {

		fmt.Println(ipPortScanList[i].IoC)

		iocExist, err := repositories.GraphRepo.FindNode(ipPortScanList[i].IoC)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		if iocExist == nil {
			err = repositories.GraphRepo.CreateIp(ipPortScanList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		ipPortScanIdExist, err := repositories.GraphRepo.FindIpPortScan(ipPortScanList[i].ID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		if ipPortScanIdExist == nil {
			err = repositories.GraphRepo.CreateIpPortScan(ipPortScanList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		err = repositories.GraphRepo.MergeIoCToIpPortScan(ipPortScanList[i].IoC, ipPortScanList[i])
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		ipPortScan, err := utils.UnmarshallPortScanPayload(ipPortScanList[i].Payload)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		for _, portItem := range ipPortScan.Host.Ports.Port {
			var portScanDetail models.PortScanDetail
			portScanDetail.ID = uuid.New().String()
			portScanDetail.Protocol = portItem.Protocol
			portScanDetail.PortNo = portItem.Portid
			portScanDetail.ServiceName = portItem.Service.Name
			portScanDetail.ServiceProduct = portItem.Service.Product
			portScanDetail.ServiceVersion = portItem.Service.Version
			portScanDetail.ServiceOsType = portItem.Service.Ostype

			//burada kaldık: portScanDetail yapısı graph üzerinde create edilmeli. ve IpPortScan ile merge edilmeli.
			err = repositories.GraphRepo.CreatePortScanDetail(&portScanDetail)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergePortScanDetailToIpPortScan(portScanDetail.ID, ipPortScanList[i].ID)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "created successfully",
		"data":    nil,
	})
}

func ImportDomainPortScan(c *fiber.Ctx) error {

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	relationshipImportRequest := &models.RelationshipImportRequest{}

	if err := c.BodyParser(relationshipImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	domainPortScanList, err := db.GetDomainPortScanList(relationshipImportRequest.Offset)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range domainPortScanList {

		fmt.Println(domainPortScanList[i].IoC)

		iocExist, err := repositories.GraphRepo.FindNode(domainPortScanList[i].IoC)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		if iocExist == nil {
			err = repositories.GraphRepo.CreateDomain(domainPortScanList[i].IoC)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		portScanIdExist, err := repositories.GraphRepo.FindDomainPortScan(domainPortScanList[i].ID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		if portScanIdExist == nil {
			err = repositories.GraphRepo.CreateDomainPortScan(domainPortScanList[i])
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		err = repositories.GraphRepo.MergeIoCToDomainPortScan(domainPortScanList[i].IoC, domainPortScanList[i])
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		domainPortScan, err := utils.UnmarshallPortScanPayload(domainPortScanList[i].Payload)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		for _, portItem := range domainPortScan.Host.Ports.Port {
			var portScanDetail models.PortScanDetail
			portScanDetail.ID = uuid.New().String()
			portScanDetail.Protocol = portItem.Protocol
			portScanDetail.PortNo = portItem.Portid
			portScanDetail.ServiceName = portItem.Service.Name
			portScanDetail.ServiceProduct = portItem.Service.Product
			portScanDetail.ServiceVersion = portItem.Service.Version
			portScanDetail.ServiceOsType = portItem.Service.Ostype

			//burada kaldık: portScanDetail yapısı graph üzerinde create edilmeli. ve IpPortScan ile merge edilmeli.
			err = repositories.GraphRepo.CreatePortScanDetail(&portScanDetail)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			err = repositories.GraphRepo.MergePortScanDetailToDomainPortScan(portScanDetail.ID, domainPortScanList[i].ID)
			// err = repositories.GraphRepo.MergePortScanDetailToIpPortScan(portScanDetail.ID, domainPortScanList[i].ID)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "created successfully",
		"data":    nil,
	})
}

func ImportCertStream(c *fiber.Ctx) error {

	db, err := database.GetDBConnection()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Error while db connection:" + err.Error(),
			"data":    nil,
		})
	}

	certStreamImportRequest := &models.CertStreamImportRequest{}

	if err := c.BodyParser(certStreamImportRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	certStreamList, err := db.GetCertStreamList(certStreamImportRequest.Offset, certStreamImportRequest.ShardingTableName)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	for i, _ := range certStreamList {

		certStreamCertificateUnmarshalled, err := utils.UnmarshallCertStreamPayload(certStreamList[i].Payload)

		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		var certStreamCertificate models.CertStreamCertificate
		certStreamCertificate.Fingerprint = certStreamCertificateUnmarshalled.LeafCert.Fingerprint
		certStreamCertificate.IssuerC = certStreamCertificateUnmarshalled.LeafCert.Issuer.C
		certStreamCertificate.IssuerO = certStreamCertificateUnmarshalled.LeafCert.Issuer.O
		certStreamCertificate.IssuerCN = certStreamCertificateUnmarshalled.LeafCert.Issuer.CN
		certStreamCertificate.NotBeforeTimestamp = certStreamCertificateUnmarshalled.LeafCert.NotBeforeStamp
		certStreamCertificate.NotAfterTimestamp = certStreamCertificateUnmarshalled.LeafCert.NotAfterStamp
		certStreamCertificate.SignatureAlgorithm = certStreamCertificateUnmarshalled.LeafCert.SignatureAlgorithm

		certStreamCertificateFingerprintExist, err := repositories.GraphRepo.FindCertStreamCertificate(certStreamCertificate.Fingerprint)

		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}

		log.Println("Fingerprint: ", certStreamCertificate.Fingerprint)
		if certStreamCertificateFingerprintExist == nil {
			err = repositories.GraphRepo.CreateCertStreamCertificate(certStreamCertificate)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for _, domain := range certStreamCertificateUnmarshalled.LeafCert.AllDomains {
			log.Println("Domain: ", domain)
			domainExist, err := repositories.GraphRepo.FindNode(domain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}

			if domainExist == nil {
				err = repositories.GraphRepo.CreateDomain(domain)
				if err != nil {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error":   true,
						"message": err,
						"data":    nil,
					})
				}
			}

			// certStreamCertificate ve certStreamCertificateUnmarshalled.LeafCert.AllDomains[k] merge ediliyor:
			err = repositories.GraphRepo.MergeCertStreamCertificateAndDomain(certStreamCertificate, domain)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"error":   false,
		"message": "Path created successfully",
		"data":    nil,
	})

}

func ImportAptReportIoCs(c *fiber.Ctx) error {

	aptReportIoCsRequest := &models.AptReportIoCsRequest{}

	if err := c.BodyParser(aptReportIoCsRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err,
			"data":    nil,
		})
	}

	// read files
	files, err := os.ReadDir("./iocs")

	if err != nil {
		log.Fatal(err)
	}

	// var uniqueIoCTypes []string

	processedFileCount := 1
	for _, f := range files {

		fmt.Println("processedFileCount: ", processedFileCount)
		processedFileCount++
		fmt.Println(f.Name())
		if f.Name() == ".DS_Store" {
			fmt.Println("Skipping .DS_Store")
			continue
		}
		lines := fileops.ReadFileLines("./son/" + f.Name())
		// lines := fileops.ReadFileLines("./APTREPORTS_IOCS/" + f.Name())

		aptReport, err := repositories.GraphRepo.FindAptReport(f.Name())
		if err != nil {
			log.Println(err.Error())
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": err,
				"data":    nil,
			})
		}
		if aptReport == nil {
			err = repositories.GraphRepo.CreateAptReport(f.Name())
			if err != nil {
				log.Println(err.Error())
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   true,
					"message": err,
					"data":    nil,
				})
			}
		}

		for _, k := range lines {
			k = strings.Trim(k, " ")
			if k == "" {
				continue
			}
			var splitted []string

			if strings.Contains(k, "\t") {
				k = strings.ReplaceAll(k, "\t", " ")
				splitted = strings.Split(k, " ")
			} else {
				splitted = strings.Split(k, ",")
			}
			if len(splitted) == 1 {
				fmt.Println("Problem!!!!!! ", f.Name())
				continue
			}

			var iocType string
			var ioc string
			var aptGroups []string

			if splitted[0] == "APTGroup" {
				iocType = splitted[0] // ioc type = "APTGroup"
				for _, k := range splitted {
					if !strings.Contains(k, "APTGroup") {
						aptGroups = append(aptGroups, strings.Trim(k, " "))
					}
				}
				ioc = aptGroups[0]

			} else {
				iocType = splitted[0]                // ioc type
				ioc = strings.Trim(splitted[1], " ") // ioc
			}

			// fmt.Println(iocType)
			// fmt.Println(ioc)
			// if ioc == "Gh0st RAT" {
			// 	fmt.Println("Gh0st RAT")
			// }

			if ioc != "" {

				if iocType == "ip4" || iocType == "ip6" {
					iocType = "ip"
				} else if iocType == "fqdn" {
					iocType = utils.ClassifyIoC(ioc)
				}

				var iocExistsInGraph *models.CyberIoC

				if iocType != "APTGroup" {
					iocExistsInGraph, err = repositories.GraphRepo.FindNode(ioc)
					if err != nil {
						return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
							"error":   true,
							"message": err,
							"data":    nil,
						})
					}
				}

				if iocExistsInGraph == nil {
					switch iocType {
					case "cve":
						err = repositories.GraphRepo.CreateIoC(ioc, "cve")
					case "domain":
						err = repositories.GraphRepo.CreateDomain(ioc)
					case "subdomain":
						err = repositories.GraphRepo.CreateSubdomain(ioc)
					case "ip":
						err = repositories.GraphRepo.CreateIp(ioc)
					case "ip4Net":
						err = repositories.GraphRepo.CreateIoC(ioc, "ip4Net")
					case "md5":
						err = repositories.GraphRepo.CreateIoC(ioc, "md5")
					case "sha1":
						err = repositories.GraphRepo.CreateIoC(ioc, "sha1")
					case "sha256":
						err = repositories.GraphRepo.CreateIoC(ioc, "sha256")
					case "tronix":
						err = repositories.GraphRepo.CreateIoC(ioc, "tronix")
					case "url":
						err = repositories.GraphRepo.CreateUrl(ioc)
					case "uuid":
						err = repositories.GraphRepo.CreateIoC(ioc, "uuid")
					case "email":
						err = repositories.GraphRepo.CreateIoC(ioc, "email")
					case "trademark":
						err = repositories.GraphRepo.CreateIoC(ioc, "trademark")
					case "copyright":
						err = repositories.GraphRepo.CreateIoC(ioc, "copyright")
					case "phoneNumber":
						err = repositories.GraphRepo.CreateIoC(ioc, "phoneNumber")
					case "githubHandle":
						err = repositories.GraphRepo.CreateIoC(ioc, "githubHandle")
					case "facebookHandle":
						err = repositories.GraphRepo.CreateIoC(ioc, "facebookHandle")
					case "linkedinHandle":
						err = repositories.GraphRepo.CreateIoC(ioc, "linkedinHandle")
					case "twitterHandle":
						err = repositories.GraphRepo.CreateIoC(ioc, "twitterHandle")
					case "youtubeChannel":
						err = repositories.GraphRepo.CreateIoC(ioc, "youtubeChannel")
					case "packageName":
						err = repositories.GraphRepo.CreateIoC(ioc, "packageName")
					case "instagramHandle":
						err = repositories.GraphRepo.CreateIoC(ioc, "instagramHandle")
					case "youtubeHandle":
						err = repositories.GraphRepo.CreateIoC(ioc, "youtubeHandle")
					case "bitcoin":
						err = repositories.GraphRepo.CreateIoC(ioc, "bitcoin")
					case "pinterestHandle":
						err = repositories.GraphRepo.CreateIoC(ioc, "pinterestHandle")
					case "ethereum":
						err = repositories.GraphRepo.CreateIoC(ioc, "ethereum")
					case "onionAddress":
						err = repositories.GraphRepo.CreateIoC(ioc, "onionAddress")
					case "Malware":
						err = repositories.GraphRepo.CreateIoC(ioc, "Malware")
					case "Filename":
						err = repositories.GraphRepo.CreateIoC(ioc, "Filename")
					case "MitreTechnique":
						err = repositories.GraphRepo.CreateIoC(ioc, "MitreTechnique")
					case "AffectedIndustry":
						err = repositories.GraphRepo.CreateIoC(ioc, "AffectedIndustry")
					case "AffectedCountry":
						err = repositories.GraphRepo.CreateIoC(ioc, "AffectedCountry")
					case "AttackerCountry":
						err = repositories.GraphRepo.CreateIoC(ioc, "AttackerCountry")
					case "C2ServerCountry":
						err = repositories.GraphRepo.CreateIoC(ioc, "C2ServerCountry")
					case "APTGroup":
						for _, k := range aptGroups {

							aptGroup, err := repositories.GraphRepo.FindAptGroup(k)
							if err != nil {
								log.Println("**** FindAptGroup error: ", err)
								continue
							}
							if aptGroup == nil {
								err = repositories.GraphRepo.CreateAptGroup(k)
								if err != nil {
									log.Println("**** CreateAptGroup error: ", err)
									continue
								}
							}
						}
					case "TerroristGroup":
						err = repositories.GraphRepo.CreateIoC(ioc, "TerroristGroup")
					case "TwitterUser":
						err = repositories.GraphRepo.CreateIoC(ioc, "TwitterUser")
					}

					if err != nil {
						return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
							"error":   true,
							"message": err,
							"data":    nil,
						})
					}
				}

				// iocNode, err := repositories.GraphRepo.FindIoCWithIoCType(ioc, iocType)
				// if err != nil {
				// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				// 		"error":   true,
				// 		"message": err,
				// 		"data":    nil,
				// 	})
				// }

				// merge recently created apt-report with recently created IoC

				if splitted[0] != "APTGroup" {

					err = repositories.GraphRepo.MergeAptReportToIoC(f.Name(), ioc, iocType)

					if err != nil {
						return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
							"error":   true,
							"message": err,
							"data":    nil,
						})
					}
				} else { // splitted[0] = "APTGroup"

					for _, k := range aptGroups {
						err = repositories.GraphRepo.MergeAptReportToAptGroup(f.Name(), k)

						if err != nil {
							return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
								"error":   true,
								"message": err,
								"data":    nil,
							})
						}
					}

					// apt groupları arasında kombinasyon uygulayarak bütün pair'lar arasında "KNOWN_AS" ilişkisi kuralım.

					// var people = ["Alice", "Bob", "Carol", "Dave", "Ed", "Mark", "Tom", "Lisa", "Sarah"];

					var totalAptGroupCount = len(aptGroups)

					if totalAptGroupCount > 1 {
						fmt.Println("ÖRNEKKKKSSSSS")
						for i := 0; i < totalAptGroupCount; i++ {
							for j := i + 1; j < totalAptGroupCount; j++ {
								aptGroup1 := aptGroups[i]
								aptGroup2 := aptGroups[j]

								foundAptGroup1, err := repositories.GraphRepo.FindAptGroup(aptGroup1)
								if err != nil {
									log.Println(err.Error())
									return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
										"error":   true,
										"message": err,
										"data":    nil,
									})
								}

								foundAptGroup2, err := repositories.GraphRepo.FindAptGroup(aptGroup2)
								if err != nil {
									log.Println(err.Error())
									return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
										"error":   true,
										"message": err,
										"data":    nil,
									})
								}

								if foundAptGroup1 == nil || foundAptGroup2 == nil {
									log.Println("APT gruplar null olmamalıydı. yukarda biyerde zaten grafa kaydetmiş olmalıydık!!!!")
								}
								err = repositories.GraphRepo.MergeAptGroups(foundAptGroup1, foundAptGroup2)
								if err != nil {
									return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
										"error":   true,
										"message": err,
										"data":    nil,
									})
								}

							}
						}
					}

				}

			}
		}

		fmt.Println("****************")
		// fmt.Println(uniqueIoCTypes)

	}
	return nil
}
