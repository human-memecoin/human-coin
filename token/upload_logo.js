const { create } = require('ipfs-http-client');
const fs = require('fs');
const path = require('path');

async function uploadToIPFS() {
    try {
        // Connect to public IPFS gateway
        const client = create('https://ipfs.infura.io:5001');

        // Read the image file
        const file = fs.readFileSync('../stick-figure1.png');
        
        // Upload to IPFS
        const added = await client.add(file);
        const logoUrl = `https://ipfs.io/ipfs/${added.path}`;
        
        console.log('Logo uploaded to:', logoUrl);
        
        // Update metadata.json with the logo URL
        const metadata = require('./metadata.json');
        metadata.image = logoUrl;
        metadata.properties.files[0].uri = logoUrl;
        
        // Upload metadata to IPFS
        const metadataAdded = await client.add(JSON.stringify(metadata));
        const metadataUrl = `https://ipfs.io/ipfs/${metadataAdded.path}`;
        
        console.log('Metadata uploaded to:', metadataUrl);
        
        // Save the URLs
        fs.writeFileSync('./urls.json', JSON.stringify({
            logo: logoUrl,
            metadata: metadataUrl
        }, null, 2));
        
        return { logoUrl, metadataUrl };
    } catch (error) {
        console.error('Error uploading to IPFS:', error);
        throw error;
    }
}

uploadToIPFS().catch(console.error);
