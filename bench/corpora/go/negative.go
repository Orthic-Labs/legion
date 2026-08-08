package fixture
func Leak(){go func(){select{}}()}
