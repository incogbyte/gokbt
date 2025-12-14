package util

import "fmt"

func PrintBanner() {
	banner := `

                __   ___.    __   
   ____   ____ |  | _\_ |___/  |_ 
  / ___\ /  _ \|  |/ /| __ \   __\
 / /_/  >  <_> )    < | \_\ \  |  
 \___  / \____/|__|_ \|___  /__|  
/_____/             \/    \/      
                                  
`
	fmt.Printf("%v\nVersion: %v (%v) - %v - %v\n\n\n", banner, Version, GitCommit, BuildDate, Author)
}
