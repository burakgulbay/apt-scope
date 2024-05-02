package queries

import (
	"cti_graph/app/models"

	"github.com/jmoiron/sqlx"
)

type WhoisQueries struct {
	*sqlx.DB
}

func (q *WhoisQueries) GetDomainWhoisList(offset int) ([]models.WhoisDomain, error) {
	query := "select * from public.whois_data_domain ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.WhoisDomain // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.WhoisDomain{}
		err := rows.Scan(

			&result.Id,
			&result.DataYear,
			&result.DataHash,
			&result.Num,
			&result.DomainName,
			&result.QueryTime,
			&result.CreateDate,
			&result.UpdateDate,
			&result.ExpiryDate,
			&result.DomainRegistrarId,
			&result.DomainRegistrarName,
			&result.DomainRegistrarWhois,
			&result.DomainRegistrarUrl,
			&result.RegistrantName,
			&result.RegistrantCompany,
			&result.RegistrantAddress,
			&result.RegistrantCity,
			&result.RegistrantState,
			&result.RegistrantZip,
			&result.RegistrantCountry,
			&result.RegistrantEmail,
			&result.RegistrantPhone,
			&result.RegistrantFax,
			&result.AdministrativeName,
			&result.AdministrativeCompany,
			&result.AdministrativeAddress,
			&result.AdministrativeCity,
			&result.AdministrativeState,
			&result.AdministrativeZip,
			&result.AdministrativeCountry,
			&result.AdministrativeEmail,
			&result.AdministrativePhone,
			&result.AdministrativeFax,
			&result.TechnicalName,
			&result.TechnicalCompany,
			&result.TechnicalAddress,
			&result.TechnicalCity,
			&result.TechnicalState,
			&result.TechnicalZip,
			&result.TechnicalCountry,
			&result.TechnicalEmail,
			&result.TechnicalPhone,
			&result.TechnicalFax,
			&result.BillingName,
			&result.BillingCompany,
			&result.BillingAddress,
			&result.BillingCity,
			&result.BillingState,
			&result.BillingZip,
			&result.BillingCountry,
			&result.BillingEmail,
			&result.BillingPhone,
			&result.BillingFax,
			&result.NameServer1,
			&result.NameServer2,
			&result.NameServer3,
			&result.NameServer4,
			&result.DomainStatus1,
			&result.DomainStatus2,
			&result.DomainStatus3,
			&result.DomainStatus4,
			&result.CreationTime,
			&result.CreationTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *WhoisQueries) GetIpWhoisList(offset int) ([]models.WhoisIp, error) {
	query := "select * from public.whois_data_ip ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.WhoisIp // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.WhoisIp{}
		err := rows.Scan(
			&result.Id,
			&result.DataYear,
			&result.DataHash,
			&result.IpAddress,
			&result.Noc,
			&result.Inetnum,
			&result.Netname,
			&result.Descr,
			&result.Country,
			&result.Organization,
			&result.AdminC,
			&result.TechC,
			&result.MntLower,
			&result.Status,
			&result.MntBy,
			&result.Created,
			&result.LastModified,
			&result.Source,
			&result.MntRoutes,
			&result.PersonName,
			&result.PersonAddress,
			&result.PersonPhone,
			&result.PersonAbuseMailbox,
			&result.PersonNicHdl,
			&result.PersonMntBy,
			&result.PersonCreated,
			&result.PersonLastModified,
			&result.PersonSource,
			&result.RouteRoute,
			&result.RouteDescr,
			&result.RouteOrigin,
			&result.RouteMntBy,
			&result.RouteCreated,
			&result.RouteLastModified,
			&result.RouteSource,
			&result.CreationTime,
			&result.CreationTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}
