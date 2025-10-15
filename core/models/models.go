package models

import "time"

type Config struct {
	AdminPasswordHash string       `json:"adminPasswordHash,omitempty"`
	PublicBaseURL     string       `json:"publicBaseUrl"`
	SAML              SAMLSettings `json:"saml"`
}

type AppData struct {
	Sites  []*Site    `json:"sites"`
	Tokens []*QRToken `json:"tokens"`
	Users  []*User    `json:"users"`
	Config Config     `json:"config"`
}

type Site struct {
	ID           string       `json:"id"`
	ShortID      string       `json:"shortId"`
	Address      string       `json:"address"`
	CustomerName string       `json:"customerName"`
	Notes        string       `json:"notes"`
	Boards       []*Board     `json:"boards"`
	Appliances   []*Appliance `json:"appliances"`
	CreatedAt    time.Time    `json:"createdAt"`
	UpdatedAt    time.Time    `json:"updatedAt"`
}

type Board struct {
	ID                string      `json:"id"`
	ShortID           string      `json:"shortId"`
	Name              string      `json:"name"`
	BoardType         string      `json:"boardType"`
	SupplyType        string      `json:"supplyType"`
	Voltage           string      `json:"voltage"`
	EarthingSystem    string      `json:"earthingSystem"`
	IncomingCable     string      `json:"incomingCable"`
	RatedCurrent      string      `json:"ratedCurrent"`
	Frequency         string      `json:"frequency"`
	Solar             bool        `json:"solar"`
	Description       string      `json:"description"`
	LastInspection    string      `json:"lastInspection"`
	NextInspectionDue string      `json:"nextInspectionDue"`
	Documents         []*Document `json:"documents"`
	CreatedAt         time.Time   `json:"createdAt"`
	UpdatedAt         time.Time   `json:"updatedAt"`
}

type ApplianceCategory string

const (
	ApplianceSolarInverter  ApplianceCategory = "Solar Inverter"
	ApplianceESS            ApplianceCategory = "ESS"
	ApplianceHeatPump       ApplianceCategory = "Heat Pump"
	ApplianceElectricBoiler ApplianceCategory = "Electric Boiler"
	ApplianceGasBoiler      ApplianceCategory = "Gas Boiler"
	ApplianceEVCharger      ApplianceCategory = "EV Charger"
)

var ApplianceCategoryOrder = []ApplianceCategory{
	ApplianceSolarInverter,
	ApplianceESS,
	ApplianceHeatPump,
	ApplianceElectricBoiler,
	ApplianceGasBoiler,
	ApplianceEVCharger,
}

type Appliance struct {
	ID            string            `json:"id"`
	Category      ApplianceCategory `json:"category"`
	Name          string            `json:"name"`
	Brand         string            `json:"brand"`
	Model         string            `json:"model"`
	SerialNumber  string            `json:"serialNumber"`
	Voltage       string            `json:"voltage"`
	PowerKW       string            `json:"powerKw"`
	InstallDate   string            `json:"installDate"`
	Notes         string            `json:"notes"`
	MPPTCount     string            `json:"mpptCount"`
	CapacityKWh   string            `json:"capacityKwh"`
	ConnectorType string            `json:"connectorType"`
	Phases        string            `json:"phases"`
	FuelType      string            `json:"fuelType"`
	Documents     []*Document       `json:"documents"`
	CreatedAt     time.Time         `json:"createdAt"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

type Document struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	FileName   string    `json:"fileName"`
	MimeType   string    `json:"mimeType"`
	FilePath   string    `json:"filePath"`
	UploadedAt time.Time `json:"uploadedAt"`
}

type QRTokenStatus string

const (
	TokenUnassigned QRTokenStatus = "UNASSIGNED"
	TokenAssigned   QRTokenStatus = "ASSIGNED"
	TokenRetired    QRTokenStatus = "RETIRED"
)

type QRToken struct {
	ID        string        `json:"id"`
	ShortID   string        `json:"shortId"`
	PIN       string        `json:"pin"`
	Status    QRTokenStatus `json:"status"`
	SiteID    string        `json:"siteId"`
	CreatedAt time.Time     `json:"createdAt"`
	UpdatedAt time.Time     `json:"updatedAt"`
}

type UserRole string

const (
	RoleOwner UserRole = "OWNER"
	RoleAdmin UserRole = "ADMIN"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"passwordHash"`
	Role         UserRole  `json:"role"`
	CreatedBy    string    `json:"createdBy"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type SAMLSettings struct {
	Enabled           bool   `json:"enabled"`
	SPBaseURL         string `json:"spBaseUrl"`
	SPEntityID        string `json:"spEntityId"`
	SPKeyPEM          string `json:"spKeyPem"`
	SPCertificatePEM  string `json:"spCertificatePem"`
	IDPMetadataURL    string `json:"idpMetadataUrl"`
	IDPMetadataXML    string `json:"idpMetadataXml"`
	EmailAttribute    string `json:"emailAttribute"`
	UsernameAttribute string `json:"usernameAttribute"`
	AllowIDPInitiated bool   `json:"allowIdpInitiated"`
}
