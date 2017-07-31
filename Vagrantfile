VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    config.vm.box = "ubuntu/xenial64"

    # Provisioning Script for initial setup and dependencies
    config.vm.provision :shell, path: "install.sh", args: ["vagrant"]

    # Django development server port forwarding
    config.vm.network "forwarded_port", guest: 8000, host: 8000

        config.vm.provider "virtualbox" do |v|
            v.memory = 1024
            v.cpus = 2
        end
end
